var liveServer = require("live-server");

var params = {
   port: 5003, // Set the server port. Defaults to 8080. 
   host: "0.0.0.0", // Set the address to bind to. Defaults to 0.0.0.0 or process.env.IP. 
   root: "/", // Set root directory that's being served. Defaults to cwd. 
   open: false, // When false, it won't load your browser by default. 
   ignore: 'scss,my/templates', // comma-separated string for paths to ignore 
   file: "index.html", // When set, serve this file for every 404 (useful for single-page applications) 
   wait: 1000, // Waits for all changes, before reloading. Defaults to 0 sec. 
   mount: [['/components', './node_modules']], // Mount a directory to a route. 
   logLevel: 2, // 0 = errors only, 1 = some, 2 = lots 
   middleware: [function(req, res, next) { next(); }] // Takes an array of Connect-compatible middleware that are injected into the server middleware stack 
};
liveServer.start(params);

function log() {
    document.getElementById('results').innerText = '';

    Array.prototype.forEach.call(arguments, function (msg) {
        if (msg instanceof Error) {
            msg = "Error: " + msg.message;
        }
        else if (typeof msg !== 'string') {
            msg = JSON.stringify(msg, null, 2);
        }
        document.getElementById('results').innerHTML += msg + '\r\n';
    });
}

document.getElementById("login").addEventListener("click", login, false);
document.getElementById("api").addEventListener("click", api, false);
document.getElementById("logout").addEventListener("click", logout, false);

var config = {
    authority: "http://localhost:5000",
    client_id: "js",
    redirect_uri: "http://localhost:5003/callback.html",
    response_type: "id_token token",
    scope:"openid profile api1",
    post_logout_redirect_uri : "http://localhost:5003/index.html",
};
var mgr = new Oidc.UserManager(config);
mgr.events.addAccessTokenExpiring();

mgr.getUser()
    .then((user) => {
        console.log(user);
        console.log(user.profile);
    });

mgr.getUser().then(function (user) {
    if (user) {
        log("User logged in", user.profile);
    }
    else {
        log("User not logged in");
    }
});

function login() {
    mgr.signinRedirect();
}

function api() {
    mgr.getUser().then(function (user) {
        var url = "http://localhost:5001/identity";

        var xhr = new XMLHttpRequest();
        xhr.open("GET", url);
        xhr.onload = function () {
            log(xhr.status, JSON.parse(xhr.responseText));
        }
        xhr.setRequestHeader("Authorization", "Bearer " + user.access_token);
        xhr.send();
    });
}

function logout() {
    mgr.signoutRedirect();
}