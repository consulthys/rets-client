var logger = require('winston'),
    utils = require('./utils.js'),
    streamBuffers = require("stream-buffers"),
    multipart = require("./multipart.js");

var objectSession;

/**
 * Retrieves RETS object data.
 *
 * @param resourceType Rets resource type (ex: Property)
 * @param objectType Rets object type (ex: LargePhoto)
 * @param objectId Object identifier
 * @param callback(error, contentType, data) (optional)
 */
var getObject = function(resourceType, objectType, objectId, callback) {
    logger.debug("RETS method getObject with params resourceType=%s, objectType=%s, objectId=%s", resourceType, objectType, objectId);

    if (!objectType || !objectId || !resourceType) {
        if (callback)
            callback(new Error("All params are required: objectType, objectId, resourceType"));

        return;
    }

    if (!objectSession) {
        if (callback)
            callback(new Error("System data not set; invoke login first."));

        return;
    }

    var objectOptions = {
        qs:{
            Type:objectType,
            Id:objectId,
            Resource:resourceType
        }
    };
    //prepare stream buffer for object data
    var writableStreamBuffer = new streamBuffers.WritableStreamBuffer({
        initialSize: (100 * 1024),      // start as 100 kilobytes.
        incrementAmount: (10 * 1024)    // grow by 10 kilobytes each time buffer overflows.
    });
    var req = objectSession(objectOptions);

    //pipe object data to stream buffer
    req.pipe(writableStreamBuffer);
    var contentType = null;
    req.on("response", function(_response){
        contentType = _response.headers["content-type"];
    });
    req.on("end", function() {
        callback(null, contentType, writableStreamBuffer.getContents());
    });
    req.on("error", function(error) {
        callback(error);
    });

};


/**
 * Helper that retrieves a list of photo objects.
 *
 * @param resourceType Rets resource type (ex: Property)
 * @param photoType Photo object type, based on getObjects meta call (ex: LargePhoto, Photo)
 * @param matrixId Photo matrix identifier.
 * @param callback(error, dataList) (optional)
 *
 *      Each item in data list is an object with the following data elements:
 *
 *       {
 *          buffer:<data buffer>,
 *          mime:<data buffer mime type>,
 *          description:<data description>,
 *          contentDescription:<data content description>,
 *          contentId:<content identifier>,
 *          objectId:<object identifier>
 *        }
 *
 */
var getPhotos = function(resourceType, photoType, matrixId, callback) {
    getObject(resourceType, photoType, matrixId, function(error, contentType, data) {
        var multipartBoundary = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i)[2];

        multipart.parseMultipart(new Buffer(data), multipartBoundary, function(error, dataList) {
            callback(error, dataList);
        });
    });
};

module.exports = function(_objectSession) {

    objectSession =_objectSession;

    return {
        getObject: getObject,
        getPhotos: getPhotos
    };
};

