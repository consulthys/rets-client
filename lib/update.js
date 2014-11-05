var logger = require('winston'),
    utils = require('./utils.js'),
    auth = require('./auth.js'),
    metadata = require('./metadata.js'),
    xmlParser = require('xml2js').parseString;

var updateSession;


/*
 * Performs RETS Update.
 *
 * @param resourceType Rets resource type (ex: Property)
 * @param classType  Rets class type (ex: RESI)
 * @param fields Fields to update
 * @param authParams Additional authorization parameters to perform delegated updates
 * @param callback(error, data) (optional)
*/
var update = function(resourceType, classType, fields, authParams, callback) {
    logger.debug("RETS method update");

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

    // add delegate headers if delegate auth data is present
    if (authParams && authParams.delegateId && authParams.delegateHash && authParams.delegatePassword) {
        updateSession.headers['X-Delegate-ID'] = authParams.delegateId;
        var retsUaAuth = updateSession.headers['rets-ua-authorization'] || undefined;
        if (retsUaAuth) {
            retsUaAuth = retsUaAuth.split("\s")[1];
            var delegateAuth = crypto.createHash('md5').update([retsUaAuth, authParams.delegatePassword, authParams.delegateHash, authParams.delegateId].join(":")).digest('hex');
            updateSession.headers['X-Delegate-Authorization'] = "Digest " + delegateAuth;
        }
    }

    var recordData = Object.keys(fields).map(function(field) {return [field, fields[field]].join("=")});
    var updateOptions = {
        qs:{
            Resource: resourceType,
            ClassName: classType,
            Validate: '0',
            Type: 'Change',
            Delimiter: '|',
            Record: recordData.join("|")
        }
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

        console.log(response.headers);
        console.log(data);

        var updateXml, delimiter, updateResults = {};
        xmlParser(data, function(err, result) {

            if (!utils.replyCodeCheck(result, callback)) return;

            updateXml = result.RETS;

            if (!utils.xmlParseCheck(updateXml, callback)) return;

            // parse transaction-id tag
            var transactionIdTag = updateXml['TRANSACTIONID'][0] || updateXml['TRANSACTION-ID'][0];
            if ('$' in transactionIdTag) updateResults.transactionId = transactionIdTag[0].$.value;
            else if (transactionIdTag) updateResults.transactionId = transactionIdTag[0];

            // get delimiter
            if (updateXml.DELIMITER) delimiter = utils.hex2a(updateXml.DELIMITER[0].$.value);

            // parse updated columns/data
            var updatedColumns = metadata.parseCompactMetadata([updateXml], "Updates");
            if ('Updates' in updatedColumns) updateResults.data = updatedColumns.Updates[0];

            // parse errors/warnings
            var reports = parseErrorWarningBlock(updateXml, delimiter);
            updateResults.errors = reports.errors;
            updateResults.warnings = reports.warnings;

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

