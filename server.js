const WebSocket = require("ws");
const Base64 = require("base-64");
const MultiplayerPiano = require("mpp-client-xt");
const fs = require("fs");

const Authenticator = require("./login.js");
const Validator = require("./validate.js");
const Friendor = require("./friends.js");
const Messengor = require("./message.js");

const WebSocketServer = new WebSocket.Server({
    port: "8080"
});
const WebSocketInterfaceServer = new WebSocket.Server({
    port: "7070",
    verifyClient: function (data){
        console.log("HERE", data)
        console.log(data)
        return true
    }
});

const ConnectedClients = {};
const OnlineUsers = {};

let WebSocketInterface;

function ParseMessage(Input) {
    let parsed;
    try {
        parsed = JSON.parse(Input);
    } catch (e) { console.log("ParsedMessage: Invalid input recieved to parse message: ", Input); };

    return parsed;
};

function ValidateClient() { };

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
    } catch (e) { console.log(`WebsocketSend: Failed to send data to client @${Websocket.ClientObject.IpAddress}.`); };
};

function OnlineUser(userConnection) {
    const { ClientObject } = userConnection;
    const { UserId, FriendsUsers } = ClientObject;

    if (UserId !== "000000000000000000000000") {
        console.log(`OnlineUser: User @${UserId} is now online!`);
        OnlineUsers[UserId] = userConnection;
        for (const userid of FriendUsers) {
            const FriendOnline = OnlineUsers[userid];
            if (FriendOnline) {
                SendData(FriendOnline, {
                    Events: ["playerOnline"],
                    Payload: { UserId }
                });
            };
        };
    };

};

function OfflineUser(ClientObject) {
    const { UserId, FriendsUsers } = ClientObject;
    delete OnlineUsers[UserId];
    
    console.log(`OnlineUser: User @${UserId} is now offline!`);
    for (const userid of FriendsUsers) {
        const FriendOnline = OnlineUsers[userid];
        if (FriendOnline) {
            SendData(FriendOnline, {
                Events: ["playerOffline"],
                Payload: { UserId }
            });
        };
    };
};

async function IncomingRequest(Websocket, RequestData) {
    const { ClientObject } = Websocket;
    const AnalyzePacket = Validator.VALIDATE_PACKET(RequestData);

    if (!AnalyzePacket) {
        return { Error: true, Message: "Invalid request data." };
    };

    const { Key, Token, CallbackId, Data } = RequestData;
    const { request } = Data;

    const RequiredAuth = {
        userAuth: true,
        message: true
    };

    if (request in RequiredAuth) {
        if (Token === null || ClientObject.AuthToken === null || Token !== ClientObject.AuthToken) {
            return false;
        };
    };

    if (Key !== "mppewebsocket") {
        return false;
    };

    let CallbackPayload;

    const ValidationFunction = Validator[request];

    if (!ValidationFunction) {
        return false;
    } else {
        const AnalysisResult = ValidationFunction(Data);
        if (!AnalysisResult) {
            return { Error: true, Message: "Invalid data in request." };
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

                if (existingUser) {
                    if (hashed === existingUser.PASSWORD) {

                        const { data } = await Friendor.getUserObject(username);

                        if (!data) {
                            return false;
                        };

                        console.log(`Authenticate: Client @${ClientObject.IpAddress} has signed into an existing account.`);

                        Websocket.ClientObject.UserInfo = {
                            ...Websocket.ClientObject.UserInfo,
                            UserId: existingUser.USERID,
                            Color: existingUser.COLOR,
                            Name: existingUser.NAME,
                            Username: username,
                            FriendUsers: data.FRIENDS,
                            BlockedUsers: data.BLOCKED
                        };

                        OnlineUser(Websocket);
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

                        SendData(Websocket, { Events: ["requestUserData"], Payload: {  } });
                        OnlineUser(Websocket);
                        GenerateAuthToken(50);
                    } else {
                        return false; // Internal error.
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
                Websocket.ClientObject.UserInfo.Color = color;
                Websocket.ClientObject.UserInfo.Name = name;
                Authenticator.editUserObject(Websocket.ClientObject.UserInfo.Username, { COLOR: color, USERID: id, NAME: name });
                OnlineUser(Websocket);
            } else {
                return false;
            };
            break;
        case "messageDM":
            const { recipient, message } = Data;
            const { UserId, Username } = Websocket.ClientObject.UserInfo;

            const { FRIENDS } = await Friendor.getUserObject(Username);

            if (FRIENDS === undefined) {
                CallbackPayload = { status: "notSent", message: "Internal error." };
                break;
            };

            const IsFriend = FRIENDS.length !== 0 && FRIENDS.indexOf(UserId) !== -1
            const ConversationHash = Authenticator.hash(recipient + UserId);
            const ConvoExists = await Messengor.conversationExist(ConversationHash);

            if (!ConvoExists) {
                console.log(`MessageDM: Creating conversation hash: ${ConversationHash}`);
                await Messengor.createConversation(ConversationHash);
            };

            const Success = await Messengor.saveMessage(ConversationHash, UserId, new Date(), message);

            if (!Success) {
                CallbackPayload = { status: "notSent", message: "Internal error." };
                break;
            } else {
                if (!IsFriend) {
                    CallbackPayload = { status: "notFriend", message: "This message was sent however, the user needs to accept your friend request to respond." };
                } else {
                    CallbackPayload = { status: "sent" };
                };
            };

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
            Room: null,
            BlockedUsers: [],
            FriendUsers: []
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
            } else if (typeof Result === "object" && CallbackId) {
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
        OfflineUser(Connection.ClientObject);

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
