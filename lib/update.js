var logger = require('winston'),
    utils = require('./utils.js'),
    auth = require('./auth.js'),
    crypto = require('crypto'),
    xmlParser = require('xml2js').parseString;

var updateSession;


/*
 * Performs RETS Update.
 *
 * @param resourceType Rets resource type (ex: Property)
 * @param classType  Rets class type (ex: RESI)
 * @param updateType the type of update to carry out (see section 11.3.4 of the RETS spec)
 * @param fields Fields to update
 * @param authParams Additional authorization parameters to perform delegated updates
 * @param callback(error, data) (optional)
*/
var update = function(resourceType, classType, updateType, fields, authParams, callback) {
    logger.debug("RETS method update with params resourceType=%s, classType=%s, updateType=%s, fields=%j, delegateId=%s",
        resourceType, classType, updateType, fields, authParams.delegateId);

    if (!resourceType || !classType || !fields) {
        if (callback)
            callback(new Error("All params are required: resourceType, classType, fields"));

        return;
    }

    if (!updateSession) {
        if (callback)
            callback(new Error("System data not set; invoke login first."));

        return;
    }

    var delegateHeaders = {};
    // add delegate headers if delegate auth data is present
    if (authParams && authParams.delegateId && authParams.delegateHash && authParams.delegatePassword) {
        // compute the RETS-UA-Authorization header so we can use it to compute delegate headers
        auth.addAuthHeaders(authParams, delegateHeaders);

        delegateHeaders['X-Delegate-ID'] = authParams.delegateId;
        if (delegateHeaders['RETS-UA-Authorization']) {
            var retsUaAuth = delegateHeaders['RETS-UA-Authorization'].split(/\s/)[1];
            var delegateAuth = crypto.createHash('md5').update([retsUaAuth, authParams.delegatePassword, authParams.delegateHash, authParams.delegateId].join(":")).digest('hex');
            delegateHeaders['X-Delegate-Authorization'] = "Digest " + delegateAuth;
        }
    }

    var recordData = Object.keys(fields).map(function(field) {return [field, fields[field]].join("=")});
    var updateOptions = {
        qs:{
            Resource: resourceType,
            ClassName: classType,
            Type: updateType,
            Validate: '0',
            Delimiter: '|',
            Record: recordData.join("|")
        },
        headers: delegateHeaders
    };

    updateSession(updateOptions, function(error, response, data) {

        var isErr = false;

        if (error) {
            isErr = true;
        }

        else if (!response) {
            isErr = true;
            error = new Error("RETS method update returned no response body");
        }

        else if (response.statusCode != 200)
        {
            isErr = true;
            error = new Error("RETS method update returned unexpected status code: " + response.statusCode);
        }

        if (isErr) {
            if (callback)
                callback(error);

            return;
        }

        var updateXml, delimiter, updateResults = {};
        xmlParser(data, function(err, result) {

            updateXml = result.RETS;

            if (!utils.xmlParseCheck(updateXml, callback)) return;

            // we don't fail if the reply code is not 0 because the response still contains useful insights
            // into what went wrong
            updateResults.replyCode = +updateXml.$.ReplyCode;
            updateResults.replyText = updateXml.$.ReplyText;

            if (updateResults.replyCode === 0) {
                // parse transaction-id tag
                var transactionIdTag = updateXml['TRANSACTIONID'][0] || updateXml['TRANSACTION-ID'][0];
                if ('$' in transactionIdTag) updateResults.transactionId = transactionIdTag.$.value;
                else if (transactionIdTag) updateResults.transactionId = transactionIdTag[0];

                // get delimiter
                if (updateXml.DELIMITER) delimiter = utils.hex2a(updateXml.DELIMITER[0].$.value);

                // parse updated columns/data
                //var updatedColumns = metadata().parseCompactMetadata([updateXml], "Updates");
                //if ('Updates' in updatedColumns) updateResults.data = updatedColumns.Updates[0];

                // parse errors/warnings
                var reports = parseErrorWarningBlock(updateXml, delimiter);
                updateResults.errors = reports.errors;
                updateResults.warnings = reports.warnings;
            } else if (!error) {
                error = updateResults.replyText + " (" + updateResults.replyCode + ")";
            }

            if(callback)
                callback(error, updateResults);

        });
    });
};

/*
 * Parses the ERRORBLOCK and WARNINGBLOCK in the Update Response body
 */
var parseErrorWarningBlock = function(updateXml, delimiter) {
    var reportObj = {errors: [], warnings: []};

    var i, delimiter = delimiter || '\t';
    if (updateXml.ERRORBLOCK) {
        for (i = 0; i < updateXml.ERRORBLOCK[0].ERRORDATA.length; i++) {
            var error = updateXml.ERRORBLOCK[0].ERRORDATA[i].split(delimiter);
            reportObj.errors.push({
                field: error[1],
                num: error[2],
                offset: error[3],
                text: error[4]
            });
        }
    }
    if (updateXml.WARNINGBLOCK) {
        for (i = 0; i < updateXml.WARNINGBLOCK[0].WARNINGDATA.length; i++) {
            var warning = updateXml.WARNINGBLOCK[0].WARNINGDATA[i].split(delimiter);
            reportObj.warnings.push({
                field: warning[1],
                num: warning[2],
                offset: warning[3],
                text: warning[4],
                responseRequired: warning[5]
            });
        }
    }

    return reportObj;
};

module.exports = function(_updateSession) {

    updateSession = _updateSession;

    return {
        update: update,
        parseErrorWarningBlock: parseErrorWarningBlock
    };
};

