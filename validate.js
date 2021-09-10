const ajv = new (require("ajv"));
const MAX_USERNAME_LENGTH = 20;
const BANNED_PASSWORD_CHARS = / -=.,\//;
const VALID_EMAIL = /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/;

const packetValidators = {
    defaultPacket: {
        type: "object",
        properties: {
            Key: { type: ["string", "null"] },
            Token: { type: "string" },
            CallbackId: { type: "number" },
            Data: {
                Type: "object",
                properties: {
                    request: { type: "string" }
                }
            },
        },
        required: ["Key", "Token", "CallbackId", "Data"],
        additionalProperties: false
    },
    encryptorPacket: {
        type: "object",
        properties: {
            username: {
                type: "string",
                minLength: 1,
                maxLength: 20
            },
            password: {
                type: "string",
                minLength: 1,
                maxLength: 25
            },
            email: {
                type: "string",
                pattern: VALID_EMAIL.source
            }
        },
        required: ["username", "password"],
        additionalProperties: false
    }
}

const encryptor = ajv.compile(encryptorPacket);
console.log(encryptor({
    username: "33333333333333333333",
    password: "3333333333333333333333333",
    email: "habibaina29@gmail.com"
}), encryptor.errors)

const Validator = {
    VALIDATE_PACKET: (Packet) => {
        if (typeof Packet !== "object") return "Invalid data packet.";
        const { Key, Token, CallbackId, Data } = Packet;

        if (typeof Key !== "string") return "Key must be string.";
        if (typeof Data !== "object") return "Data must be object.";

        if (Token !== null && typeof Token !== "string") return "Token must be string.";
        if (CallbackId !== null && typeof CallbackId !== "number") return "CallbackId must be number.";

        const { request } = Data;

        if (typeof request !== "string") return "request must be string.";

        return true;
    },
    getEncryptor: (_) => {
        return true;
    },
    authenticate: ({ username, email, password }) => {
        if (typeof username !== "string") return "Username must be string.";
        if (typeof password !== "string") return "Password must be string.";
        if (email && typeof email !== "string") return "Email must be string.";

        if (username.length > MAX_USERNAME_LENGTH) return "Username is too long.";

        if (email && !VALID_EMAIL.test(email)) return "Email is invalid.";
        if (BANNED_PASSWORD_CHARS.test(password)) return "Password contains invalid characters.";

        return true;
    },
    userAuth: ({ Id }) => {
        if (typeof Id !== "string") return "Id must be string.";
        if (Id.length > 30) return "Id is invalid.";

        return true;
    }
};

module.exports = Validator;