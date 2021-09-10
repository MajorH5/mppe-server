const WebSocket = require("ws");
const Base64 = require("base-64");
const Authenticator = require("./login.js");
const Validator = require("./validate.js");
const MultiplayerPiano = require("mpp-client-xt");

const WebSocketServer = new WebSocket.Server({
    port: "8080"
});
const WebSocketInterfaceServer = new WebSocket.Server({
    port: "7070"
});

const ConnectedClients = {};

let WebSocketInterface;

function ParseMessage(Input) {
    let parsed;
    try {
        parsed = JSON.parse(Input);
    } catch (e) { console.log("ParsedMessage: Invalid input recieved to parse message: ", Input); };

    return parsed;
};

function AuthenticateId(AuthenticationRoom, ExpectedAuthCode, ExpectedUserId) {
    const MultiplayerPianoClient = new MultiplayerPiano();
    MultiplayerPianoClient.desiredChannelSettings = { visible: false };

    const VerificationPromise = new Promise((resolve) => {
        MultiplayerPianoClient.setChannel(AuthenticationRoom);
        MultiplayerPianoClient.start();
        MultiplayerPianoClient.on("a", ({ a: AuthenticationCode, p: PlayerDetails }) => {
            const { id } = PlayerDetails;
            if (id === ExpectedUserId && ExpectedAuthCode === AuthenticationCode) {
                MultiplayerPianoClient.stop();
                console.log(`AuthenticateId: User @${ExpectedUserId}'s identity has been verified.`);
                resolve({ Verified: true, PlayerObject: PlayerDetails });
            };
        });
    });

    const Timeout = 15 * 1000; // Stop verification after 15 seconds.
    const TimeoutPromise = new Promise((resolve) => {
        const TimeoutWait = setTimeout(_ => {
            MultiplayerPianoClient.stop();
            clearTimeout(TimeoutWait);
            resolve({ Verified: false });
        }, Timeout);
    });

    return Promise.race([TimeoutPromise, VerificationPromise]);
};

function UnloadClients(Websocket, Clients) {
    for (const IpAddress in Clients) {
        const { ClientObject } = Clients[IpAddress];
        try {
            Websocket.send(JSON.stringify({
                Command: "newClient",
                IpAddress: IpAddress,
                ConnectTime: ClientObject.ConnectTime,
                PacketsSent: 0,
                PacketsReceived: 0,
                IsConnected: true
            }));
        } catch (e) { console.log(`UnloadClients: Failed to send client @${IpAddress} to interface.`) };
    };
};

function SendData(Websocket, Data) {
    const SendingPayload = {
        Key: "mppewebsocket",
        ...Data
    };

    SendingPayload.Events ||= [];
    SendingPayload.Type ||= "default";
    SendingPayload.CallbackId ||= 0;

    try {
        Websocket.send(JSON.stringify(SendingPayload));
    } catch (e) { console.log(`WebsocketSend: Failed to send data to Client @${Websocket.ClientObject.IpAddress}.`); };
};

async function IncomingRequest(Websocket, RequestData) {
    const { ClientObject } = Websocket;
    const AnalyzePacket = Validator.VALIDATE_PACKET(RequestData);
    const HasInfo = Object.values(ClientObject.UserInfo).every(Value => Value !== null);

    if (typeof AnalyzePacket === "string") {
        return { Error: true, Message: AnalyzePacket };
    };

    const { Key, Token, CallbackId, Data } = RequestData;

    const { request } = Data;

    const RequiredAuth = {
        userAuth: true,
        message: true
    };

    if (request in RequiredAuth) {
        if (Token === null || ClientObject.AuthToken === null || Token !== ClientObject.AuthToken){
            return false;
        }
    };

    if (Key !== "mppewebsocket") {
        return false;
    };

    let CallbackPayload;

    const ValidationFunction = Validator[request];

    if (!ValidationFunction){
        return false;
    }else{
        const AnalysisResult = ValidationFunction(Data);
        if (typeof AnalysisResult === "string"){
            return { Error: true, Message: AnalysisResult };
        };
    };

    switch (request) {
        case "getEncryptor":
            const encryptor = Authenticator.generateEncryptor(30);
            Websocket.encryptor = encryptor;
            CallbackPayload = { encryptor };
            break;
        case "authenticate":
            if (Websocket.encryptor) {
                const { username, password, email } = Data;

                const { Result } = await Authenticator.getUserObject(username);
                if (!Result) {
                    return false; // Internal error.
                };

                const GenerateAuthToken = (size) => {
                    const authtoken = "mppe_AUTH-" + Authenticator.generateEncryptor(size, true);
                    Websocket.ClientObject.AuthToken = authtoken;
                    CallbackPayload = { authToken: authtoken };
                    return authtoken
                };

                const [existingUser] = Result;

                const decryptor = Authenticator.decrypt(Websocket.encryptor)
                const rawPassword = decryptor(Base64.decode(password));
                const hashed = Authenticator.hash(rawPassword);

                if (rawPassword.length > 25) return { Error: true, Message: "Password is too long." };

                if (existingUser) {
                    if (hashed === existingUser.PASSWORD) {
                        console.log(`Authenticate: Client @${ClientObject.IpAddress} has signed into an existing account.`);
                        Websocket.ClientObject.UserInfo = {
                            UserId: existingUser.USERID,
                            Color: existingUser.COLOR,
                            Name: existingUser.NAME,
                            Username: username
                        };
                        GenerateAuthToken(50);
                    };
                } else {
                    const { Success } = await Authenticator.createAccount({
                        IpAddress: ClientObject.IpAddress,
                        UserId: ClientObject.UserId || "000000000000000000000000",
                        Name: ClientObject.Name || "Anonymous",
                        Color: ClientObject.Color || "#FFFFFF",
                        Username: username,
                        Password: rawPassword,
                        Email: email
                    });
                    Websocket.ClientObject.Username = username;
                    if (Success) {
                        console.log(`Authenticate: Client @${ClientObject.IpAddress} has created account.`);
                        GenerateAuthToken(50);
                    } else {
                        return false;
                    };

                };

            };
            break;
        case "userAuth":
            if (Websocket.UserAuth) {
                return false;
            };
            Websocket.UserAuth = true;

            const { Id } = Data;

            const AuthenticationCode = Authenticator.generateEncryptor(20, true);
            const AuthenticationRoom = "mppe-authroom_" + Authenticator.generateEncryptor(10, true);

            SendData(Websocket, {
                Type: "callback",
                CallbackId: CallbackId,
                Payload: { AuthenticationRoom, AuthenticationCode }
            });

            const { Verified, PlayerObject } = await AuthenticateId(AuthenticationRoom, AuthenticationCode, Id);

            Websocket.UserAuth = false;

            if (Verified) {
                const { _id, name, color, id } = PlayerObject;
                Websocket.ClientObject.UserInfo.UserId = id;
                Websocket.ClientObject.UserInfo.User_Id = _id;
                Websocket.ClientObject.UserInfo.Color = color;;
                Websocket.ClientObject.UserInfo.Name = name
                Authenticator.editUserObject(Websocket.ClientObject.UserInfo.Username, { COLOR: color, USERID: id, NAME: name });
            } else {
                return false;
            };
            break;
        case "message":
            const { recipient, message } = Data;
            const { UserId } = Websocket.ClientObject.UserInfo;

            const ConversationHash = Authenticator.hash(recipient + UserId);

            
            

            break;
    };

    if (CallbackPayload) {
        SendData(Websocket, {
            Type: "callback",
            Payload: CallbackPayload,
            CallbackId: CallbackId
        });
    };

    return true;
};

function WebSocketConnection(Connection, Request) {
    const RawIp = Request.connection.remoteAddress.split(":");
    const ClientObject = {
        IpAddress: RawIp[RawIp.length - 1],
        ConnectTime: new Date(),
        AuthToken: null,
        UserInfo: {
            Username: null,
            UserId: null,
            User_Id: null,
            Color: null,
            Name: null,
            BlockedUsers: []
        },
    };
    console.log(`WebsocketConnect: Client @${ClientObject.IpAddress} has connected!`);

    Connection.ClientObject = ClientObject;
    ConnectedClients[ClientObject.IpAddress] = Connection;

    if (WebSocketInterface) {
        UnloadClients(WebSocketInterface, { [ClientObject.IpAddress]: Connection })
    };

    Connection.on("message", async function WebsocketMessage(Data) {
        const ParsedMessage = ParseMessage(Data);
        if (ParsedMessage) {
            const { CallbackId } = ParsedMessage;
            const Result = await IncomingRequest(Connection, ParsedMessage);

            if (typeof Result === "boolean" && !Result && CallbackId) {
                SendData(Connection, {
                    Type: "callback",
                    CallbackId: CallbackId,
                    Payload: { Error: true }
                });
            }else if (typeof Result === "object" && CallbackId) {
                SendData(Connection, {
                    Type: "callback",
                    CallbackId: CallbackId,
                    Payload: Result
                })
            };
        } else {
            Connection.close();
        };
    });

    Connection.on("close", function WebSocketClose() {
        console.log(`WebsocketDisconnect: Client @${ClientObject.IpAddress} has disconnected!`);
        delete ConnectedClients[ClientObject.IpAddress];

        if (WebSocketInterface) {
            WebSocketInterface.send(JSON.stringify({
                Command: "removeClient",
                Target: ClientObject.IpAddress
            }));
        };
    });
};

WebSocketServer.on("connection", WebSocketConnection);


/* WEBSOCKET SERVER INTERFACE CODE */

WebSocketInterfaceServer.on("connection", function WebSocketInterfaceConnection(Interface) {
    UnloadClients(Interface, ConnectedClients);

    WebSocketInterface = Interface;
    Interface.on("message", function WebSocketInterfaceCommand(CommandObject) {
        CommandObject = JSON.parse(CommandObject);
        const { Command, Target, Message } = CommandObject;
        for (const IpAddress in ConnectedClients) {
            if (IpAddress === Target) {
                switch (Command) {
                    case "Disconnect":
                        const TargetConnection = ConnectedClients[IpAddress];
                        if (Message) {
                            try {
                                TargetConnection.send(JSON.stringify({
                                    ServerSideDisconnection: true,
                                    Message: "Your connection was terminated by Admin."
                                }));
                            } catch (e) { console.log(`InterfaceDisconnect: Failed to send disconnect message to client @${IpAddress}.`) }
                        };
                        TargetConnection.close();
                        console.log(TargetConnection.readyState)
                        break;
                }
            };
        };
    });
    Interface.on("close", function WebSocketDisconnectInterface() {
        WebSocketInterface = null;
    });
});
