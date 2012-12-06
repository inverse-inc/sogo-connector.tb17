/* sogoWebDAV.js - This file is part of "SOGo Connector", a Thunderbird extension.
 *
 * Copyright: Inverse inc., 2006-2010
 *    Author: Robert Bolduc, Wolfgang Sourdeau
 *     Email: support@inverse.ca
 *       URL: http://inverse.ca
 *
 * "SOGo Connector" is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation;
 *
 * "SOGo Connector" is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * "SOGo Connector"; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

function jsInclude(files, target) {
    let loader = Components.classes["@mozilla.org/moz/jssubscript-loader;1"]
                           .getService(Components.interfaces.mozIJSSubScriptLoader);
    for (let i = 0; i < files.length; i++) {
        try {
            loader.loadSubScript(files[i], target);
        }
        catch(e) {
            dump("sogoWebDAV.js: failed to include '" + files[i] +
                 "'\n" + e
                 + "\nFile: " + e.fileName
                 + "\nLine: " + e.lineNumber + "\n\n Stack:\n\n" + e.stack);
        }
    }
}

jsInclude(["chrome://inverse-library/content/uuid.js"]);

function backtrace(aDepth) {
    let depth = aDepth || 10;
    let stack = "";
    let frame = arguments.callee.caller;

    for (let i = 1; i <= depth && frame; i++) {
        stack += i+": "+ frame.name + "\n";
        frame = frame.caller;
    }

    return stack;
}

function XMLToJSONParser(doc) {
    this._buildTree(doc);
}

XMLToJSONParser.prototype = {
    _buildTree: function XMLToJSONParser_buildTree(doc) {
        let nodeName = doc.documentElement.localName;
        this[nodeName] = [this._translateNode(doc.documentElement)];

        // 		dump("Parsed XMLToJSON object: " + dumpObject(this) + "\n");
    },
    _translateNode: function XMLToJSONParser_translateNode(node) {
        let value = null;

        if (node.childNodes.length) {
            let textValue = "";
            let dictValue = {};
            let hasElements = false;
            for (let i = 0; i < node.childNodes.length; i++) {
                let currentNode = node.childNodes[i];
                let nodeName = currentNode.localName;
                if (currentNode.nodeType
                    == Components.interfaces.nsIDOMNode.TEXT_NODE)
                    textValue += currentNode.nodeValue;
                else if (currentNode.nodeType
                         == Components.interfaces.nsIDOMNode.ELEMENT_NODE) {
                    hasElements = true;
                    let nodeValue = this._translateNode(currentNode);
                    if (!dictValue[nodeName])
                        dictValue[nodeName] = [];
                    dictValue[nodeName].push(nodeValue);
                }
            }

            if (hasElements)
                value = dictValue;
            else
                value = textValue;
        }

        return value;
    }
};

function xmlEscape(text) {
    let s = "";

    for (var i = 0; i < text.length; i++) {
        if (text[i] == "&") {
            s += "&amp;";
        }
        else if (text[i] == "<") {
            s += "&lt;";
        }
        else  {
            let charCode = text.charCodeAt(i);
            if (charCode > 127) {
                s += '&#' + charCode + ';';
            }
            else {
                s += text[i];
            }
        }
    }

    return s;
}

function xmlUnescape(text) {
    let s = (""+text).replace(/&lt;/g, "<", "g");
    s = s.replace(/&gt;/g, ">", "g");
    s = s.replace(/&amp;/g, "&",  "g");

    return s;
}

/* from Lightning: cal.auth.Prompt */
/**
 * Calendar Auth prompt implementation. This instance of the auth prompt should
 * be used by providers and other components that handle authentication using
 * nsIAuthPrompt2 and friends.
 *
 * This implementation guarantees there are no request loops when an invalid
 * password is stored in the login-manager.
 *
 * There is one instance of that object per calendar provider.
 */
function _sogoWebDAVPrompt() {
    this.mReturnedLogins = {};
}

_sogoWebDAVPrompt.prototype = {
    passwordManagerRemove: function calPasswordManagerRemove(aUsername, aHostName, aRealm) {
        try {
            let loginManager = Components.classes["@mozilla.org/login-manager;1"]
                                         .getService(Components.interfaces.nsILoginManager);
            let logins = loginManager.findLogins({}, aHostName, null, aRealm);
            for each (let loginInfo in logins) {
                if (loginInfo.username == aUsername) {
                    loginManager.removeLogin(loginInfo);
                    return true;
                }
            }
        } catch (exc) {
        }
        return false;
    },

    getPasswordInfo: function capGPI(aPasswordRealm) {
        let username;
        let password;
        let found = false;

        let loginManager = Components.classes["@mozilla.org/login-manager;1"]
                                     .getService(Components.interfaces.nsILoginManager);
        let logins = loginManager.findLogins({}, aPasswordRealm.prePath, null, aPasswordRealm.realm);
        if (logins.length) {
            username = logins[0].username;
            password = logins[0].password;
            found = true;
        }
        if (found) {
            let keyStr = aPasswordRealm.prePath +":" + aPasswordRealm.realm;
            let now = new Date();
            // Remove the saved password if it was already returned less
            // than 60 seconds ago. The reason for the timestamp check is that
            // nsIHttpChannel can call the nsIAuthPrompt2 interface
            // again in some situation. ie: When using Digest auth token
            // expires.
            if (this.mReturnedLogins[keyStr] &&
                now.getTime() - this.mReturnedLogins[keyStr].getTime() < 60000) {
                // cal.LOG("Credentials removed for: user=" + username + ", host="+aPasswordRealm.prePath+", realm="+aPasswordRealm.realm);
                delete this.mReturnedLogins[keyStr];
                this.passwordManagerRemove(username,
                                           aPasswordRealm.prePath,
                                           aPasswordRealm.realm);
                return {found: false, username: username};
            }
            else {
                this.mReturnedLogins[keyStr] = now;
            }
        }
        return {found: found, username: username, password: password};
    },

    /**
     * Requests a username and a password. Implementations will commonly show a
     * dialog with a username and password field, depending on flags also a
     * domain field.
     *
     * @param aChannel
     *        The channel that requires authentication.
     * @param level
     *        One of the level constants NONE, PW_ENCRYPTED, SECURE.
     * @param authInfo
     *        Authentication information object. The implementation should fill in
     *        this object with the information entered by the user before
     *        returning.
     *
     * @retval true
     *         Authentication can proceed using the values in the authInfo
     *         object.
     * @retval false
     *         Authentication should be cancelled, usually because the user did
     *         not provide username/password.
     *
     * @note   Exceptions thrown from this function will be treated like a
     *         return value of false.
     */
    promptAuth: function capPA(aChannel, aLevel, aAuthInfo) {
        let hostRealm = {};
        hostRealm.prePath = aChannel.URI.prePath;
        hostRealm.realm = aAuthInfo.realm;
        let port = aChannel.URI.port;
        if (port == -1) {
            let IOService = Components.classes["@mozilla.org/network/io-service;1"]
                                      .getService(Components.interfaces.nsIIOService2);
            let handler = IOService.getProtocolHandler(aChannel.URI.scheme)
                                   .QueryInterface(Components.interfaces.nsIProtocolHandler);
            port = handler.defaultPort;
        }
        hostRealm.passwordRealm = aChannel.URI.host + ":" + port + " (" + aAuthInfo.realm + ")";

        let pw = this.getPasswordInfo(hostRealm);
        aAuthInfo.username = pw.username;
        if (pw && pw.found) {
            aAuthInfo.password = pw.password;
            return true;
        } else {
            let prompter2 = Components.classes["@mozilla.org/embedcomp/window-watcher;1"]
                                      .getService(Components.interfaces.nsIPromptFactory)
                                      .getPrompt(null, Components.interfaces.nsIAuthPrompt2);
            return prompter2.promptAuth(aChannel, aLevel, aAuthInfo);
        }
    },

    /**
     * Asynchronously prompt the user for a username and password.
     * This has largely the same semantics as promptAuth(),
     * but must return immediately after calling and return the entered
     * data in a callback.
     *
     * If the user closes the dialog using a cancel button or similar,
     * the callback's nsIAuthPromptCallback::onAuthCancelled method must be
     * called.
     * Calling nsICancelable::cancel on the returned object SHOULD close the
     * dialog and MUST call nsIAuthPromptCallback::onAuthCancelled on the provided
     * callback.
     *
     * @throw NS_ERROR_NOT_IMPLEMENTED
     *        Asynchronous authentication prompts are not supported;
     *        the caller should fall back to promptUsernameAndPassword().
     */
    asyncPromptAuth : function capAPA(aChannel,   // nsIChannel
                                      aCallback,  // nsIAuthPromptCallback
                                      aContext,   // nsISupports
                                      aLevel,     // PRUint32
                                      aAuthInfo   // nsIAuthInformation
                                ) {
        let hostRealm = {};
        hostRealm.prePath = aChannel.URI.prePath;
        hostRealm.realm = aAuthInfo.realm;
        let port = aChannel.URI.port;
        if (port == -1) {
            let IOService = Components.classes["@mozilla.org/network/io-service;1"]
                                      .getService(Components.interfaces.nsIIOService2);

            let handler = IOService.getProtocolHandler(aChannel.URI.scheme)
                                   .QueryInterface(Components.interfaces.nsIProtocolHandler);
            port = handler.defaultPort;
        }
        hostRealm.passwordRealm = aChannel.URI.host + ":" + port + " (" + aAuthInfo.realm + ")";

        let pw = this.getPasswordInfo(hostRealm);
        aAuthInfo.username = pw.username;
        if (pw && pw.found) {
            aAuthInfo.password = pw.password;
            // We cannot call the callback directly here so call it from a timer
            let timerCallback = {
                notify: function(timer) {
                    aCallback.onAuthAvailable(aContext, aAuthInfo);
                }
            };
            let timer = Components.classes["@mozilla.org/timer;1"]
                        .createInstance(Components.interfaces.nsITimer);
            timer.initWithCallback(timerCallback,
                                   0,
                                   Components.interfaces.nsITimer.TYPE_ONE_SHOT);
        } else {
            let prompter2 = Components.classes["@mozilla.org/embedcomp/window-watcher;1"]
                                      .getService(Components.interfaces.nsIPromptFactory)
                                      .getPrompt(null, Components.interfaces.nsIAuthPrompt2);
            prompter2.asyncPromptAuth(aChannel, aCallback, aContext, aLevel, aAuthInfo);
        }
    }
};

/* from Lightning: cal.BadCertHandler */
/**
 * Bad Certificate Handler for Network Requests. Shows the Network Exception
 * Dialog if a certificate Problem occurs.
 */
let _sogoWebDAVBadCertHandler = function calBadCertHandler(thisProvider) {
    this.thisProvider = thisProvider;
};

_sogoWebDAVBadCertHandler.prototype = {
    QueryInterface: function cBCL_QueryInterface(aIID) {
        if (!aIID.equals(Components.interfaces.nsIBadCertListener2)
            && !aIID.equals(Components.interfaces.nsISupports))
            throw Components.results.NS_ERROR_NO_INTERFACE;
        return this;
    },

    notifyCertProblem: function cBCL_notifyCertProblem(socketInfo, status, targetSite) {
        if (!status) {
            return true;
        }

        // Unfortunately we can't pass js objects using the window watcher, so
        // we'll just take the first available calendar window. We also need to
        // do this on a timer so that the modal window doesn't block the
        // network request.
        let wm = Components.classes["@mozilla.org/appshell/window-mediator;1"]
                           .getService(Components.interfaces.nsIWindowMediator);
        let calWindow = wm.getMostRecentWindow("calendarMainWindow") ||
                        wm.getMostRecentWindow("mail:3pane");

        let timerCallback = {
            thisProvider: this.thisProvider,
            notify: function(timer) {
                let params = { exceptionAdded: false,
                               prefetchCert: true,
                               location: targetSite };
                calWindow.openDialog("chrome://pippki/content/exceptionDialog.xul",
                                     "",
                                     "chrome,centerscreen,modal",
                                     params);
                if (this.thisProvider.canRefresh &&
                    params.exceptionAdded) {
                    // Refresh the provider if the
                    // exception certificate was added
                    this.thisProvider.refresh();
                }
            }
        };
        let timer = Components.classes["@mozilla.org/timer;1"]
                              .createInstance(Components.interfaces.nsITimer);
        timer.initWithCallback(timerCallback,
                               0,
                               Components.interfaces.nsITimer.TYPE_ONE_SHOT);
        return true;
    }
};

function sogoWebDAV(url, target, data, synchronous) {
    this.url = url;
    this.target = target;
    this.cbData = data;
    this.requestJSONResponse = false;
    this.requestXMLResponse = false;
    if (typeof synchronous == "undefined") {
        this.synchronous = false;
    }
    else {
        this.synchronous = synchronous;
    }
}

sogoWebDAV.prototype = {
    _makeURI: function _makeURI(url) {
        var ioSvc = Components.classes["@mozilla.org/network/io-service;1"].
            getService(Components.interfaces.nsIIOService);
        return ioSvc.newURI(url, null, null);
    },

    /* The following method code comes as-is from Lightning (cal.InterfaceRequestor_getInterface): */
    _getInterface: function sogoWebDAV_getInterface(aIID) {
        // Support Auth Prompt Interfaces
        if (aIID.equals(Components.interfaces.nsIAuthPrompt2)) {
            return new _sogoWebDAVPrompt();
        } else if (aIID.equals(Components.interfaces.nsIAuthPromptProvider) ||
                   aIID.equals(Components.interfaces.nsIPrompt)) {
            return Components.classes["@mozilla.org/embedcomp/window-watcher;1"]
                .getService(Components.interfaces.nsIWindowWatcher)
                .getNewPrompter(null);
        } else if (aIID.equals(Components.interfaces.nsIBadCertListener2)) {
            return new _sogoWebDAVBadCertHandler(this);
        } else if (aIID.equals(Components.interfaces.nsIProgressEventSink)) {
            return { onProgress: function sogoWebDAV_onProgress(aRequest, aContext, aProgress, aProgressMax) {},
                     onStatus: function sogoWebDAV_onStatus(aRequest, aContext, aStatus, aStatusArg) {} };
        }

        dump("no interface in sogoWebDAV named " + aIID + "\n");

        throw Components.results.NS_ERROR_NO_INTERFACE;

//         Components.returnCode = Components.NS_ERROR_NO_INTERFACE;
//         return null;
    },

    _sendHTTPRequest: function(method, body, headers) {
        let IOService = Components.classes["@mozilla.org/network/io-service;1"]
                                  .getService(Components.interfaces.nsIIOService2);
        let channel = IOService.newChannelFromURI(this._makeURI(this.url));
        let httpChannel = channel.QueryInterface(Components.interfaces.nsIHttpChannel);
        httpChannel.loadFlags |= Components.interfaces.nsIRequest.LOAD_BYPASS_CACHE;
        httpChannel.notificationCallbacks = { getInterface: this._getInterface };
        httpChannel.setRequestHeader("accept", "text/xml", false);
        httpChannel.setRequestHeader("accept-charset", "utf-8,*;q=0.1", false);
        if (headers) {
            for (let header in headers) {
                httpChannel.setRequestHeader(header, headers[header], true);
            }
        }

        if (body) {
            httpChannel = httpChannel.QueryInterface(Components.interfaces.nsIUploadChannel);
            let converter = Components.classes["@mozilla.org/intl/scriptableunicodeconverter"]
                                      .createInstance(Components.interfaces.nsIScriptableUnicodeConverter);
            converter.charset = "UTF-8";
            let stream = converter.convertToInputStream(body);
            let contentType = headers["content-type"];
            if (!contentType) {
                contentType = "text/plain; charset=utf-8";
            }
            httpChannel.setUploadStream(stream, contentType, -1);
        }

        /* If set too early, the method can change to "PUT" when initially set to "PROPFIND"... */
        httpChannel.requestMethod = method;

        if (this.synchronous) {
            let inStream = httpChannel.open();
            let byteStream = Components.classes["@mozilla.org/binaryinputstream;1"]
                                       .createInstance(Components.interfaces.nsIBinaryInputStream);
            byteStream.setInputStream(inStream);
            let resultLength = 0;
            let result = "";
            let le;
            while ((le = inStream.available())) {
                resultLength += le;
                result += byteStream.readBytes(le);
            }
            this._handleHTTPResponse(httpChannel, resultLength, result);
        }
        else {
            let this_ = this;
            let listener = {
                onStreamComplete: function(aLoader, aContext, aStatus, aResultLength, aResult) {
                    this_._handleHTTPResponse(httpChannel, aResultLength, aResult);
                }
            };
            let loader = Components.classes["@mozilla.org/network/stream-loader;1"]
                                   .createInstance(Components.interfaces.nsIStreamLoader);
            loader.init(listener);
            httpChannel.asyncOpen(loader, httpChannel);
        }
    },

    _handleHTTPResponse: function(aChannel, aResultLength, aResult) {
        let status;
        try {
            status = aChannel.responseStatus;
            if (status == 0) {
                status = 499;
            }
        }
        catch(e) {
            dump("sogoWebDAV: trapped exception: " + e + "\n");
            setTimeout("throw new Error('sogoWebDAV could not download calendar. Try disabling proxy server.')",0); 
            status = 499;
        }
        try {
            let headers = {};
            let response = null;
            if (status == 499) {
                dump("xmlRequest: received status 499 for url: " + this.url + "\n");
            }
            else {
                let visitor = {};
                visitor.visitHeader = function(aHeader, aValue) {
                    let key = aHeader.toLowerCase();
                    let array = headers[key];
                    if (!array) {
                        array = [];
                        headers[key] = array;
                    }
                    array.push(aValue.replace(/(^[ 	]+|[ 	]+$)/, "", "g"));
                };
                aChannel.visitResponseHeaders(visitor);
                if (aResultLength > 0) {
                    let responseText;
                    if (typeof(aResult) == "string") {
                        responseText = aResult;
                    }
                    else {
                        let resultConverter = Components.classes["@mozilla.org/intl/scriptableunicodeconverter"]
                                                        .createInstance(Components.interfaces.nsIScriptableUnicodeConverter);
                        resultConverter.charset ="UTF-8";
                        responseText = resultConverter.convertFromByteArray(aResult, aResultLength);
                    }
                    if (this.requestJSONResponse || this.requestXMLResponse) {
                        let flatCType = (headers["content-type"] ? headers["content-type"][0] : "");

                        if ((flatCType.indexOf("text/xml") == 0 || flatCType.indexOf("application/xml") == 0)
                            && aResultLength > 0) {
                            let xmlParser = Components.classes["@mozilla.org/xmlextras/domparser;1"]
                                                      .createInstance(Components.interfaces.nsIDOMParser);
                            let responseXML = xmlParser.parseFromString(responseText, "text/xml");
                            if (this.requestJSONResponse) {
                                let parser = new XMLToJSONParser(responseXML);
                                response = parser;
                            }
                            else {
                                response = responseXML;
                            }
                        }
                    }
                    else {
                        response = responseText;
                    }
                }
            }
            if (this.target && this.target.onDAVQueryComplete) {
                this.target.onDAVQueryComplete(status, response, headers, this.cbData);
            }
        }
        catch(e) {
            dump("sogoWebDAV.js: an exception occured\n" + e + "\n"
                 + e.fileName + ":" + e.lineNumber + "\n");
            let uri = aChannel.URI;
            if (uri) {
                dump("url: " + uri.spec + "\n");
            }
        }
    },

    load: function(operation, parameters) {
        if (operation == "GET") {
            this._sendHTTPRequest(operation);
        }
        else if (operation == "PUT" || operation == "POST") {
            this._sendHTTPRequest(operation,
                                  parameters.data,
                                  { "content-type": parameters.contentType });
        }
        else if (operation == "PROPFIND") {
            let headers = { "depth": (parameters.deep
                                      ? "1": "0"),
                            "content-type": "application/xml; charset=utf8" };
            let query = this._propfindQuery(parameters.props);
            this._sendHTTPRequest(operation, query, headers);
        }
        else if (operation == "REPORT") {
            let headers = { "depth": (parameters.deep
                                      ? "1": "0"),
                            "Connection": "TE",
                            "TE": "trailers",
                            "content-type": "application/xml; charset=utf8" };
            this._sendHTTPRequest(operation, parameters.query, headers);
        }
        else if (operation == "MKCOL") {
            this._sendHTTPRequest(operation, parameters);
        }
        else if (operation == "DELETE") {
            this._sendHTTPRequest(operation, parameters);
        }
        else if (operation == "PROPPATCH") {
            let headers = { "content-type": "application/xml; charset=utf8" };
            this._sendHTTPRequest(operation, parameters, headers);
        }
        else if (operation == "OPTIONS") {
            this._sendHTTPRequest(operation, parameters);
        }
        else
            throw ("operation '" + operation + "' is not currently supported");
    },
    get: function() {
        this.load("GET");
    },
    put: function(data, contentType) {
        this.load("PUT", {data: data, contentType: contentType});
    },
    post: function(data, contentType) {
        if (typeof(contentType) == "undefined") {
            contentType = "application/xml; charset=utf8";
        }
        this.load("POST", {data: data, contentType: contentType});
    },
    _propfindQuery: function(props) {
        let nsDict = { "DAV:": "D" };
        let propPart = "";
        let nsCount = 0;
        for each (let prop in props) {
            let propParts = prop.split(" ");
            let ns = propParts[0];
            let nsS = nsDict[ns];
            if (!nsS) {
                nsS = "x" + nsCount;
                nsDict[ns] = nsS;
                nsCount++;
            }
            propPart += "<" + nsS + ":" + propParts[1] + "/>";
        }
        let query = ("<?xml version=\"1.0\"?>\n"
                     + "<D:propfind");
        for (let ns in nsDict)
            query += " xmlns:" + nsDict[ns] + "=\"" + ns + "\"";
        query += ("><D:prop>" + propPart + "</D:prop></D:propfind>");

        return query;
    },
    options: function() {
        this.load("OPTIONS");
    },
    propfind: function(props, deep) {
        this.requestJSONResponse = true;
        if (typeof deep == "undefined")
            deep = true;
        this.load("PROPFIND", {props: props, deep: deep});
    },
    mkcol: function() {
        this.load("MKCOL");
    },
    delete: function() {
        this.load("DELETE");
    },
    report: function(query, deep) {
        if (typeof deep == "undefined")
            deep = true;
        this.load("REPORT", {query: query, deep: deep});
    },
    proppatch: function(query) {
        this.requestJSONResponse = true;
        this.load("PROPPATCH", query);
    }
};
