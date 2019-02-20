var logger = require('winston'),
    xmlParser = require('xml2js').parseString,
    request = require('request'),
    crypto = require('crypto');
require('request-debug')(request);

/**
 * Executes RETS login routine.
 * @param settings.loginUrl RETS login URL (i.e http://<MLS_DOMAIN>/rets/login.ashx)
 * @param settings.username username credential
 * @param settings.password password credential
 * @param settings.userAgent the user-agent to use
 * @param settings.userAgentPassword the user-agent password to use
 * @param settings.version the RETS version
 * @param callback(error, client)
 */
var login = function(settings, callback) {

    logger.debug("Rets method login");

    var headers = {
        'User-Agent': "Node-Rets/1.0",
        'RETS-Version': settings.version || 'RETS/1.7.2'
    };
    addAuthHeaders(settings, headers);

    // prepare a base request template that will be used by all sub-modules
    // so that cookies can be shared/reused/managed
    var cookieJar = request.jar();
    var retsSession = request.defaults({
        uri: settings.loginUrl,
        jar: cookieJar,
        headers: headers,
        auth: {
            username: settings.username,
            password: settings.password,
            sendImmediately: false
        }
    });

    retsSession({}, function(error, response, body) {
        var isErr = false;

        if (error) {
            isErr = true;
        }

        if (response && response.statusCode != 200)
        {
            isErr = true;
            var errMsg = "RETS method login returned unexpected HTTP status code: " + response.statusCode;
            error = new Error(errMsg);
            error.replyCode = response.statusCode;
            error.replyText = errMsg;
        }

        if (isErr) {
            if (callback)
                callback(error);

            return;
        }
        var retsXml;
        xmlParser(body, function(err, result) {

            if (!result || !result.RETS ||!result.RETS["RETS-RESPONSE"]) {
                if (callback)
                    callback(new Error("Unexpected results. Please check the URL: " + settings.loginUrl));
                return;
            }

            retsXml = result.RETS["RETS-RESPONSE"];
            var keyVals = retsXml[0].split("\r\n");

            var systemData = {};

            for(var i = 0; i < keyVals.length; i++)
            {
                var keyValSplit = keyVals[i].split("=");
                if (keyValSplit.length > 1) {
                    systemData[keyValSplit[0]] = keyValSplit[1];
                }
            }

            systemData.retsVersion = response.headers["rets-version"];
            systemData.retsServer = response.headers.server;

            cookieJar.getCookies(settings.loginUrl).forEach(function(cookie) {
                if (cookie.key === 'RETS-Session-ID') {
                    systemData.sessionId = cookie.value;
                }
            });

            if (callback)
                callback(error, systemData, retsSession);
        });
    });
};

/**
 * Logouts RETS user
 * @param logoutRequest a pre-configured request to properly log out
 * @param callback(error)
 *
 * @event logout.success Logout was successful
 * @event logout.failure(error) Logout failure
 *
 */
var logout = function(logoutRequest, callback) {

    logger.debug("RETS method logout");

    logoutRequest({}, function(error, response, body) {

        var isErr = false;

        if (error) {
            isErr = true;
        }

        if (response.statusCode != 200)
        {
            isErr = true;

            var errMsg = "RETS method logout returned unexpected status code: " + response.statusCode;
            error = new Error(errMsg);
            error.replyCode = response.statusCode;
            error.replyText = errMsg;
        }

        if (isErr) {
            if (callback)
                callback(error);

            return;
        }

        logger.debug("Logout success");

        if (callback)
            callback(error, true);
    });
};

/**
 * Creates additional headers for elevated authorization rights
 * @param settings hash containing additional settings for creating authorization headers
 * @param the modifiable headers hash
 */
var addAuthHeaders = function(settings, headers) {
    if (!settings || !headers || typeof headers !== 'object') return;

    // use specified user agent
    if (settings.userAgent) {
        headers['User-Agent'] = settings.userAgent;

        // add RETS-UA-Authorization header
        if (settings.userAgentPassword) {
            var a1 = crypto.createHash('md5').update([settings.userAgent, settings.userAgentPassword].join(":")).digest('hex');
            var retsUaAuth = crypto.createHash('md5').update([a1, "", settings.sessionId || "", settings.version || headers['RETS-Version']].join(":")).digest('hex');
            headers['RETS-UA-Authorization'] = "Digest " + retsUaAuth;
        }
    }
};

module.exports.login = login;
module.exports.logout = logout;
module.exports.addAuthHeaders = addAuthHeaders;
