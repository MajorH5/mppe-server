const mysql = require("mysql");
const { promiseQuery } = require("./login.js");

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "MPPE@Server-1",
    database: "mppe_UP_db"
});

async function getFriendsList(username) {
    const query = `SELECT * FROM mppe_f_db.global_friends WHERE USERNAME = '${username}'`;
    let { Result } = await promiseQuery(query);

    if (!Result) return false;
    if (Result.length === 0) {
        const createQuery = `INSERT INTO mppe_f_db.global_friends VALUES('${username}', '["FriendedMe!"]', '["BlockedMe!"]')`;
        let { Result } = await promiseQuery(createQuery);
        
        if (!Result) return false;
        return [];
    };
    
    const [ dataObject ] = Result;

    return dataObject.FRIENDS;
};

async function setFriendsList(username) {

};

async function canMessage() {

};

async function friendUser() {

};

async function unfriendUser() {

};

async function isBlocked() {

};

async function blockUser() {

};

async function unblockUser() {

};

db.connect(async (error) => {
    if (error) {
        throw error;
    };
    const data = await getFriendsList("qewqeqw");
    console.log(data)
});

module.exports = Object.freeze({

});