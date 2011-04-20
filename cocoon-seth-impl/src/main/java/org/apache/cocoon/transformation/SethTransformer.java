/*
    SethTransformer - written in May 2004
    * updated 2005 for hackfest
    * updated 2009 for ssl sockets/certificate handling
    * updated 2011 for google api, page identification

    all work by me is (c) Copyright GNU General Public License (GPL)
    @author <a href="http://projectconifer.ca/library">art rhyno</a>
*/
package org.apache.cocoon.transformation;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;

import java.net.*;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.stream.XMLStreamException;

import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.Vector;

import org.apache.avalon.framework.parameters.Parameters;
import org.apache.avalon.framework.service.ServiceException;
import org.apache.avalon.framework.service.ServiceManager;
import org.apache.cocoon.ProcessingException;
import org.apache.cocoon.caching.CacheableProcessingComponent;
import org.apache.cocoon.components.sax.XMLByteStreamCompiler;
import org.apache.cocoon.components.sax.XMLByteStreamInterpreter;
import org.apache.cocoon.components.source.SourceUtil;
import org.apache.cocoon.environment.SourceResolver;
import org.apache.cocoon.transformation.helpers.IncludeCacheManager;
import org.apache.cocoon.transformation.helpers.IncludeCacheManagerSession;
import org.apache.cocoon.xml.IncludeXMLConsumer;
import org.apache.cocoon.xml.XMLConsumer;
import org.apache.cocoon.xml.XMLUtils;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.excalibur.source.Source;
import org.apache.excalibur.source.SourceException;
import org.apache.excalibur.source.SourceParameters;
import org.apache.excalibur.source.SourceValidity;
import org.apache.excalibur.xml.dom.DOMParser;
import org.apache.excalibur.xml.xpath.XPathProcessor;

import org.apache.commons.httpclient.*;
import org.apache.commons.httpclient.auth.AuthPolicy;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.util.HttpURLConnection;
import org.apache.commons.httpclient.cookie.CookiePolicy;
import org.apache.commons.httpclient.methods.*;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.util.URIUtil;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.regexp.RE;
import org.apache.regexp.RESyntaxException;

import org.xml.sax.Attributes;
import org.xml.sax.ext.LexicalHandler;
import org.xml.sax.helpers.AttributesImpl;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;

import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.tidy.Tidy;

public class SethTransformer extends AbstractTransformer {

    public static final String my_uri = "http://seth.sourceforge.net";
    public static final String my_name = "SethTransformer";

    /** Outgoing tags */
    public static final String RESULTS_ELEMENT = "retrieval-results";
    public static final String URL_ELEMENT = "url";
    public static final String RESPONSE_ELEMENT = "responses";
    public static final String REQUEST_ELEMENT = "requests";
    public static final String COOKIES_ELEMENT = "cookies";
    public static final String CONTENTS_ELEMENT = "contents";
    public static final String REGEXP_ELEMENT = "regexpval";
    public static final String RESULT_CODE = "code";
    public static final String RESULT_PAGES = "pages";
    public static final String RESULT_PAGE = "page";
    public static final String RESULT_JSON = "json";

    /** Our allowed tags */
    public static final String MAGIC_EXECUTE_RETRIEVAL = "execute-retrieval";
    public static final String MAGIC_URL_ELEMENT = "url";
    public static final String MAGIC_USERNAME_ELEMENT = "username";
    public static final String MAGIC_AUTHSUB_ELEMENT = "authsub";
    public static final String MAGIC_VOLUME_ELEMENT = "volume";
    public static final String MAGIC_PASSWORD_ELEMENT = "password";
    public static final String MAGIC_LIMIT_ELEMENT = "limit";
    public static final String MAGIC_USERAGENT_ELEMENT = "useragent";
    public static final String MAGIC_TIMEOUT_ELEMENT = "timeout";
    public static final String MAGIC_XMLONLY_ELEMENT = "xmlonly";
    public static final String MAGIC_JSONONLY_ELEMENT = "jsononly";
    public static final String MAGIC_SIFT_ELEMENT = "sift";
    public static final String MAGIC_REDIRECT_LIMIT_ELEMENT = "redirect_limit";
    public static final String MAGIC_REGEXP_ELEMENT = "regexp";
    public static final String MAGIC_NVP_ELEMENT = "nvp";
    public static final String MAGIC_COOKIE_ELEMENT = "cookie";
    public static final String MAGIC_METHOD_ELEMENT = "method";
    public static final String MAGIC_REDIRECT_ELEMENT = "redirect";
    public static final String MAGIC_DEBUG_ELEMENT = "debug";

    /** The states we are allowed to be in */
    public static final int STATE_OUTSIDE = 0;
    public static final int STATE_INSIDE_EXECUTE_RETRIEVAL = 1;
    public static final int STATE_INSIDE_URL_ELEMENT = 2;
    public static final int STATE_INSIDE_USERNAME_ELEMENT = 3;
    public static final int STATE_INSIDE_AUTHSUB_ELEMENT = 4;
    public static final int STATE_INSIDE_VOLUME_ELEMENT = 5;
    public static final int STATE_INSIDE_PASSWORD_ELEMENT = 6;
    public static final int STATE_INSIDE_LIMIT_ELEMENT = 7;
    public static final int STATE_INSIDE_USERAGENT_ELEMENT = 8;
    public static final int STATE_INSIDE_TIMEOUT_ELEMENT = 9;
    public static final int STATE_INSIDE_XMLONLY_ELEMENT = 10;
    public static final int STATE_INSIDE_JSONONLY_ELEMENT = 11;
    public static final int STATE_INSIDE_SIFT_ELEMENT = 12;
    public static final int STATE_INSIDE_REDIRECT_LIMIT_ELEMENT = 13;
    public static final int STATE_INSIDE_REGEXP_ELEMENT = 14;
    public static final int STATE_INSIDE_NVP_ELEMENT = 15;
    public static final int STATE_INSIDE_COOKIE_ELEMENT = 16;
    public static final int STATE_INSIDE_METHOD_ELEMENT = 17;
    public static final int STATE_INSIDE_REDIRECT_ELEMENT = 18;
    public static final int STATE_INSIDE_DEBUG_ELEMENT = 19;

    /** Default parameters that might apply to all retrievals */
    protected Properties default_properties = new Properties();

    /** The name of the value element we're currently receiving */
    protected String current_name;

    /** The current state of the event receiving FSM */
    protected int current_state = STATE_OUTSIDE;

    /** The value of the value element we're currently receiving */
    protected StringBuffer current_value = new StringBuffer();

    /** The list of retrievals that we're currently working on */
    protected Vector retrievals = new Vector();

    /** The offset of the current retrieval in the retrievals list */
    protected int current_retrieval_index = -1;

    /** SAX producing state information */
    protected XMLConsumer xml_consumer;
    protected LexicalHandler lexical_handler;

    /** BEGIN SitemapComponent methods */

    public void setup(SourceResolver resolver, Map objectModel, String source, Parameters parameters)
        throws ProcessingException, SAXException, IOException {

        current_state = STATE_OUTSIDE;

        String parameter;

        // Check the url
        parameter = parameters.getParameter(MAGIC_URL_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_URL_ELEMENT, parameter);
        }

        // Check the username
        parameter = parameters.getParameter(MAGIC_USERNAME_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_USERNAME_ELEMENT, parameter);
        }

        // Check the password
        parameter = parameters.getParameter(MAGIC_PASSWORD_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_PASSWORD_ELEMENT, parameter);
        }

        // Check the authsub
        parameter = parameters.getParameter(MAGIC_AUTHSUB_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_AUTHSUB_ELEMENT, parameter);
        }
        // Check the volume
        parameter = parameters.getParameter(MAGIC_VOLUME_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_VOLUME_ELEMENT, parameter);
        }

        // Check the limit
        parameter = parameters.getParameter(MAGIC_LIMIT_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_LIMIT_ELEMENT, parameter);
        }

        // Check the useragent
        parameter = parameters.getParameter(MAGIC_USERAGENT_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_USERAGENT_ELEMENT, parameter);
        }

        // Check the timeout
        parameter = parameters.getParameter(MAGIC_TIMEOUT_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_TIMEOUT_ELEMENT, parameter);
        }

        // Check the xmlonly
        parameter = parameters.getParameter(MAGIC_XMLONLY_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_XMLONLY_ELEMENT, parameter);
        }

        // Check the jsononly
        parameter = parameters.getParameter(MAGIC_JSONONLY_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_JSONONLY_ELEMENT, parameter);
        }

        // Check the sift
        parameter = parameters.getParameter(MAGIC_SIFT_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_SIFT_ELEMENT, parameter);
        }

        // Check the redirect_limit
        parameter = parameters.getParameter(MAGIC_REDIRECT_LIMIT_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_REDIRECT_LIMIT_ELEMENT, parameter);
        }

        // Check the regexp
        parameter = parameters.getParameter(MAGIC_REGEXP_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_REGEXP_ELEMENT, parameter);
        }

        // Check the method
        parameter = parameters.getParameter(MAGIC_METHOD_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_METHOD_ELEMENT, parameter);
        }

        // Check the nvp
        parameter = parameters.getParameter(MAGIC_NVP_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_NVP_ELEMENT, parameter);
        }

        // Check the cookie
        parameter = parameters.getParameter(MAGIC_COOKIE_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_COOKIE_ELEMENT, parameter);
        }

        // Check the redirect element
        parameter = parameters.getParameter(MAGIC_REDIRECT_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_REDIRECT_ELEMENT, parameter);
        }

        // Check the debug element
        parameter = parameters.getParameter(MAGIC_DEBUG_ELEMENT, null);
        if (parameter != null) {
            default_properties.setProperty(MAGIC_DEBUG_ELEMENT, parameter);
        }

    }

    /** END SitemapComponent methods */

    /**
     * This will be the meat of SethTransformer, where the retrieval is run.
     */
    protected void executeRetrieval(int index) throws SAXException {
        // this.contentHandler.startPrefixMapping("", SethTransformer.my_uri);
        HTMLRetrieval retrieval = (HTMLRetrieval) retrievals.elementAt(index);
        try {
            retrieval.execute();
        } catch (Exception e) {
        System.out.println("error " + e.toString());
            getLogger().error(e.toString());
            throw new SAXException(e);
        }

        this.contentHandler.endPrefixMapping("");
    }

    protected static void throwIllegalStateException(String message) {
        throw new IllegalStateException(my_name + ": " + message);
    }

    /** Move into elements */
    protected void startExecuteRetrieval(Attributes attributes) {
        HTMLRetrieval retrieval;
        switch (current_state) {
            case SethTransformer.STATE_OUTSIDE :
                current_state = SethTransformer.STATE_INSIDE_EXECUTE_RETRIEVAL;
                current_retrieval_index = retrievals.size();
                retrieval = new HTMLRetrieval(this);
                retrievals.addElement(retrieval);
                getCurrentRetrieval().toDo = SethTransformer.STATE_INSIDE_EXECUTE_RETRIEVAL;
                getCurrentRetrieval().retrieval_index = current_retrieval_index;
                break;
            default :
                throwIllegalStateException("Not expecting a start execute-retrieval element");
        }
    }

    protected void endExecuteRetrieval() throws SAXException {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                executeRetrieval(current_retrieval_index);
                retrievals.remove(current_retrieval_index);
                --current_retrieval_index;
                if (current_retrieval_index > -1) {
                    current_state = getCurrentRetrieval().toDo;
                } else {
                    retrievals.removeAllElements();
                    current_state = SethTransformer.STATE_OUTSIDE;
                }
                break;
            default :
                throwIllegalStateException("Not expecting a end execute-retrieval element");
        }
    }

    protected void startNvpElement(Attributes attributes) {
        String thisName = attributes.getValue("name");

        if (thisName != null) 
            getCurrentRetrieval().nvpName = thisName;
        else
            throwIllegalStateException("value without name");

        String checkJsonSpace = attributes.getValue("jsspace");
        if (checkJsonSpace != null)
            getCurrentRetrieval().jsspace = checkJsonSpace;
        
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_NVP_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start nvp element");
        }
    }

    protected void endNvpElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_NVP_ELEMENT :
                String parmVal = current_value.toString().trim();
                //examples of extra encoding options
                /*
                try {
                    parmVal = URIUtil.encodeQuery(parmVal);
                } catch (URIException uriEx) {
                    System.out.println("prob: " + uriEx.toString());
                    parmVal = current_value.toString().trim();
                } */
                /*
                try {
                    parmVal = URLEncoder.encode(parmVal,"UTF-8");
                } catch (UnsupportedEncodingException uriEx) {
                    System.out.println("prob: " + uriEx.toString());
                    parmVal = current_value.toString().trim();
                }
                */

                //we can't always rely on uri encodings for whitespaces
                if (getCurrentRetrieval().jsspace != null)
                    parmVal = parmVal.replaceAll(" ","\\\\u0020");

                NameValuePair thisNVP = new NameValuePair(
                        getCurrentRetrieval().nvpName,
                        parmVal);
                
                getCurrentRetrieval().nvps.addElement(thisNVP);
                current_state = getCurrentRetrieval().toDo; 
                break; 
            default : 
                throwIllegalStateException("Not expecting a end nvp element");
            }//switch
    }//endNvpElement

    protected void startCookieElement(Attributes attributes) {
        String checkDomain = attributes.getValue("domain");
        if (checkDomain != null)
            getCurrentRetrieval().thisDomain = checkDomain;

        if (checkDomain == null) {
            try {
                InetAddress localaddr = InetAddress.getLocalHost();
                String thisHost = localaddr.getHostAddress().toString();
            
                int firstPart = thisHost.indexOf(".");
                if (firstPart != -1)
                    getCurrentRetrieval().thisDomain = thisHost.substring(firstPart);
        
            } catch (UnknownHostException uhe) {
                getCurrentRetrieval().thisDomain = "*";
            }//try
    
        }//if

        getCurrentRetrieval().thisName = attributes.getValue("name");
        getCurrentRetrieval().thisPath = attributes.getValue("path");
    
        String checkDate = attributes.getValue("date");
    
        if (checkDate != null) {
            DateFormat theFormat = new 
                SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy");
            try {
                getCurrentRetrieval().thisDate = 
                    theFormat.parse(checkDate);
            } catch (Exception e) {
                throwIllegalStateException("Problem with cookie date");
            }
        }//if

        String checkAge = attributes.getValue("age");
        if (checkAge != null)
            getCurrentRetrieval().thisAge = Integer.parseInt(checkAge);
    
        String checkSecure = attributes.getValue("secure");
        if (checkSecure != null) {
            if (checkSecure.trim().toUpperCase().equals("TRUE"))
                getCurrentRetrieval().isSecure = true;
        }//if

        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_COOKIE_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start cookie element");
        }//switch
    }

    protected void endCookieElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_COOKIE_ELEMENT :
        String thisValue = current_value.toString().trim();
        Cookie thisCookie;

        if (getCurrentRetrieval().thisPath != null &&
            getCurrentRetrieval().thisDate != null)
        {
        thisCookie = new Cookie(getCurrentRetrieval().thisDomain, 
            getCurrentRetrieval().thisName, 
            thisValue,
            getCurrentRetrieval().thisPath,
            getCurrentRetrieval().thisDate,
            getCurrentRetrieval().isSecure);
        } else if (getCurrentRetrieval().thisPath != null &&
            getCurrentRetrieval().thisAge >= 0)
        {
        thisCookie = new Cookie(getCurrentRetrieval().thisDomain, 
            getCurrentRetrieval().thisName, 
            thisValue,
            getCurrentRetrieval().thisPath,
            getCurrentRetrieval().thisAge,
            getCurrentRetrieval().isSecure);
        } else {
        thisCookie = new Cookie(getCurrentRetrieval().thisDomain, 
            getCurrentRetrieval().thisName, 
            thisValue);
        }
                getCurrentRetrieval().sethcookies.addElement(thisCookie);
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end cookie element");
        }
    }

    protected void startMethodElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_METHOD_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start method element");
        }
    }

    protected void endMethodElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_METHOD_ELEMENT :
                getCurrentRetrieval().method = current_value.toString().trim().toUpperCase();
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end method element");
        }
    }

    protected void startUrlElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_URL_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start url element");
        }
    }

    protected void endUrlElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_URL_ELEMENT :
                getCurrentRetrieval().url = current_value.toString();
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end url element");
        }
    }

    protected void startUsernameElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_USERNAME_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start username element");
        }
    }

    protected void endUsernameElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_USERNAME_ELEMENT :
                getCurrentRetrieval().username = current_value.toString();
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end username element");
        }
    }

    protected void startAuthsubElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_AUTHSUB_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start authsub element");
        }
    }

    protected void endAuthsubElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_AUTHSUB_ELEMENT :
                getCurrentRetrieval().authsub = current_value.toString();
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end authsub element");
        }
    }

    protected void startVolumeElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_VOLUME_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start volume element");
        }
    }

    protected void endVolumeElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_VOLUME_ELEMENT :
                getCurrentRetrieval().volume = current_value.toString();
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end volume element");
        }
    }

    protected void startPasswordElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_PASSWORD_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start password element");
        }
    }

    protected void endPasswordElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_PASSWORD_ELEMENT :
                getCurrentRetrieval().password = current_value.toString();
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end password element");
        }
    }

    protected void startLimitElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_LIMIT_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start limit element");
        }
    }

    protected void endLimitElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_LIMIT_ELEMENT :
                getCurrentRetrieval().limit = current_value.toString().trim().toUpperCase();
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end limit element");
        }
    }
    protected void startUserAgentElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_USERAGENT_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start useragent element");
        }
    }

    protected void endUserAgentElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_USERAGENT_ELEMENT :
                getCurrentRetrieval().useragent = current_value.toString().trim();
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end useragent element");
        }
    }

    protected void startXmlonlyElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_XMLONLY_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start xmlonly element");
        }
    }

    protected void endXmlonlyElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_XMLONLY_ELEMENT :
                if (current_value.toString().toUpperCase().equals("TRUE")) {
                    getCurrentRetrieval().xmlonly = true;
                }
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end xmlonly element");
        }
    }

    protected void startJsononlyElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_JSONONLY_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start jsononly element");
        }
    }

    protected void endJsononlyElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_JSONONLY_ELEMENT :
                if (current_value.toString().toUpperCase().equals("TRUE")) {
                    getCurrentRetrieval().jsononly = true;
                }
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end jsononly element");
        }
    }

    protected void startSiftElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_SIFT_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start sift element");
        }
    }

    protected void endSiftElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_SIFT_ELEMENT :
                getCurrentRetrieval().sift = current_value.toString();
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end sift element");
        }
    }

    protected void startTimeoutElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_TIMEOUT_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start timeout element");
        }
    }

    protected void endTimeoutElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_TIMEOUT_ELEMENT :
                getCurrentRetrieval().timeout = Integer.parseInt(current_value.toString());
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end timeout element");
        }
    }

    protected void startRedirectLimitElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_REDIRECT_LIMIT_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start redirect_limit element");
        }
    }

    protected void endRedirectLimitElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_REDIRECT_LIMIT_ELEMENT :
                getCurrentRetrieval().redirect_limit = Integer.parseInt(current_value.toString());
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end redirect_limit element");
        }
    }

    protected void startRegExpElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_REGEXP_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start regexp element");
        }
    }

    protected void endRegExpElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_REGEXP_ELEMENT :
                getCurrentRetrieval().regexp = current_value.toString();
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end regexp element");
        }
    }
 
    protected void startRedirectElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_REDIRECT_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start redirect element");
        }
    }

    protected void endRedirectElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_REDIRECT_ELEMENT :
                if (current_value.toString().toUpperCase().equals("FALSE")) {
                    getCurrentRetrieval().redirect = false;
                }
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end redirect element");
        }
    }

    protected void startDebugElement(Attributes attributes) {
        switch (current_state) {
            case STATE_INSIDE_EXECUTE_RETRIEVAL :
                current_value.setLength(0);
                current_state = SethTransformer.STATE_INSIDE_DEBUG_ELEMENT;
                break;
            default :
                throwIllegalStateException("Not expecting a start debug element");
        }
    }

    protected void endDebugElement() {
        switch (current_state) {
            case SethTransformer.STATE_INSIDE_DEBUG_ELEMENT :
                if (current_value.toString().toUpperCase().equals("TRUE")) {
                    getCurrentRetrieval().debug = true;
                }
                current_state = getCurrentRetrieval().toDo;
                break;
            default :
                throwIllegalStateException("Not expecting a end debug element");
        }
    }

    protected HTMLRetrieval getCurrentRetrieval() {
        return (HTMLRetrieval) retrievals.elementAt(current_retrieval_index);
    }

    protected HTMLRetrieval getRetrieval(int i) {
        return (HTMLRetrieval) retrievals.elementAt(i);
    }

    /** END my very own methods */

    /** BEGIN SAX ContentHandler handlers */

    public void setDocumentLocator(Locator locator) {
        if (getLogger().isDebugEnabled()) {
            getLogger().debug("PUBLIC ID: " + locator.getPublicId());
            getLogger().debug("SYSTEM ID: " + locator.getSystemId());
        }
        if (super.contentHandler != null)
            super.contentHandler.setDocumentLocator(locator);
    }

    public void startElement(String uri, String name, String raw, Attributes attributes) throws SAXException {
        if (!uri.equals(my_uri)) {
            super.startElement(uri, name, raw, attributes);
            return;
        }
        getLogger().debug("RECEIVED START ELEMENT " + name + "(" + uri + ")");

        if (name.equals(SethTransformer.MAGIC_EXECUTE_RETRIEVAL)) {
            startExecuteRetrieval(attributes);
        } else if (name.equals(SethTransformer.MAGIC_NVP_ELEMENT)) {
            startNvpElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_COOKIE_ELEMENT)) {
            startCookieElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_METHOD_ELEMENT)) {
            startMethodElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_URL_ELEMENT)) {
            startUrlElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_USERNAME_ELEMENT)) {
            startUsernameElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_AUTHSUB_ELEMENT)) {
            startAuthsubElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_VOLUME_ELEMENT)) {
            startVolumeElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_PASSWORD_ELEMENT)) {
            startPasswordElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_LIMIT_ELEMENT)) {
            startLimitElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_USERAGENT_ELEMENT)) {
            startUserAgentElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_XMLONLY_ELEMENT)) {
            startXmlonlyElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_JSONONLY_ELEMENT)) {
            startJsononlyElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_SIFT_ELEMENT)) {
            startSiftElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_TIMEOUT_ELEMENT)) {
            startTimeoutElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_REDIRECT_LIMIT_ELEMENT)) {
            startRedirectLimitElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_REGEXP_ELEMENT)) {
            startRegExpElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_REDIRECT_ELEMENT)) {
            startRedirectElement(attributes);
        } else if (name.equals(SethTransformer.MAGIC_DEBUG_ELEMENT)) {
            startDebugElement(attributes);
        }
    }

    public void endElement(String uri, String name, String raw) throws SAXException {
        if (!uri.equals(my_uri)) {
            super.endElement(uri, name, raw);
            return;
        }
        getLogger().debug("RECEIVED END ELEMENT " + name + "(" + uri + ")");

        if (name.equals(SethTransformer.MAGIC_EXECUTE_RETRIEVAL)) {
            endExecuteRetrieval();
        } else if (name.equals(SethTransformer.MAGIC_NVP_ELEMENT)) {
            endNvpElement();
        } else if (name.equals(SethTransformer.MAGIC_COOKIE_ELEMENT)) {
            endCookieElement();
        } else if (name.equals(SethTransformer.MAGIC_METHOD_ELEMENT)) {
            endMethodElement();
        } else if (name.equals(SethTransformer.MAGIC_URL_ELEMENT)) {
            endUrlElement();
        } else if (name.equals(SethTransformer.MAGIC_USERNAME_ELEMENT)) {
            endUsernameElement();
        } else if (name.equals(SethTransformer.MAGIC_AUTHSUB_ELEMENT)) {
            endAuthsubElement();
        } else if (name.equals(SethTransformer.MAGIC_VOLUME_ELEMENT)) {
            endVolumeElement();
        } else if (name.equals(SethTransformer.MAGIC_PASSWORD_ELEMENT)) {
            endPasswordElement();
        } else if (name.equals(SethTransformer.MAGIC_LIMIT_ELEMENT)) {
            endLimitElement();
        } else if (name.equals(SethTransformer.MAGIC_USERAGENT_ELEMENT)) {
            endUserAgentElement();
        } else if (name.equals(SethTransformer.MAGIC_XMLONLY_ELEMENT)) {
            endXmlonlyElement();
        } else if (name.equals(SethTransformer.MAGIC_JSONONLY_ELEMENT)) {
            endJsononlyElement();
        } else if (name.equals(SethTransformer.MAGIC_SIFT_ELEMENT)) {
            endSiftElement();
        } else if (name.equals(SethTransformer.MAGIC_TIMEOUT_ELEMENT)) {
            endTimeoutElement();
        } else if (name.equals(SethTransformer.MAGIC_REDIRECT_LIMIT_ELEMENT)) {
            endRedirectLimitElement();
        } else if (name.equals(SethTransformer.MAGIC_REGEXP_ELEMENT)) {
            endRegExpElement();
        } else if (name.equals(SethTransformer.MAGIC_REDIRECT_ELEMENT)) {
            endRedirectElement();
        } else if (name.equals(SethTransformer.MAGIC_DEBUG_ELEMENT)) {
            endDebugElement();
        }
    }

    public void characters(char ary[], int start, int length) throws SAXException {
        if (current_state != SethTransformer.STATE_INSIDE_NVP_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_COOKIE_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_METHOD_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_URL_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_USERNAME_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_AUTHSUB_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_VOLUME_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_PASSWORD_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_LIMIT_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_USERAGENT_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_XMLONLY_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_JSONONLY_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_SIFT_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_TIMEOUT_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_REDIRECT_LIMIT_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_REGEXP_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_REDIRECT_ELEMENT
            && current_state != SethTransformer.STATE_INSIDE_DEBUG_ELEMENT) 
        {
            super.characters(ary, start, length);
        }
        getLogger().debug("RECEIVED CHARACTERS: " + new String(ary, start, length));
        current_value.append(ary, start, length);
    }

    private void attribute(AttributesImpl attr, String name, String value) {
        attr.addAttribute("", name, name, "CDATA", value);
    }

    private void start(String name, AttributesImpl attr) throws SAXException {
        super.contentHandler.startElement("", name, name, attr);
        attr.clear();
    }

    private void end(String name) throws SAXException {
        super.contentHandler.endElement("", name, name);
    }

    private void data(String data) throws SAXException {
        if (data != null)
            super.contentHandler.characters(data.toCharArray(), 0, data.length());
    }

    protected static String getStringValue(Object object) {
        if (object instanceof byte[]) {
            return new String((byte[]) object);
        } else if (object instanceof char[]) {
            return new String((char[]) object);
        } else if (object != null) {
            return object.toString();
        } else {
            return "";
        }
    }


    class HTMLRetrieval {

        /** Index for retrievals list */
        protected int retrieval_index;

        /** The current state of the event */
        protected int current_state;

        protected SethTransformer transformer;

        protected String url = "http://127.0.0.1";

        protected String username = null;

        protected String password = null;

        protected String authsub = null;

        protected String volume = null;

        protected String limit = null;

        protected String useragent = null;

        protected int timeout = 0;

        protected boolean xmlonly = false;

        protected boolean jsononly = false;

        protected String sift = null;

        protected int redirect_limit = 5;
        
        protected int result = 0;

        protected String regexp = null;

        protected RE sethRE;

        protected String method = "GET";

        protected String cookieType = "NAME";

        protected Vector nvps = new Vector();

        protected Vector sethcookies = new Vector();

        protected int toDo;

        //NVP values
        protected String nvpName = null;
        protected String jsspace = null;

        //Cookie values
        protected String thisDomain = null;
        protected String thisName = null;
        protected String thisPath = null;
        protected Date thisDate = null;
        protected int thisAge = -1;
        protected boolean isSecure = false;

        protected int sequence = 1;

        protected StringBuffer textBucket = new StringBuffer();
        
        protected AttributesImpl attr = new AttributesImpl();

        protected HttpClient _httpClient;

        protected HttpMethod _httpMethod;

        protected boolean redirect = true;

        protected int limitTagBlock = 0;

        protected boolean debug = false;

        //work through elements
        protected HTMLRetrieval(SethTransformer transformer) {
            this.transformer = transformer;

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_NVP_ELEMENT)) 
            {
                nvps.addElement(transformer.default_properties.
                    getProperty(SethTransformer.
                    MAGIC_NVP_ELEMENT));
            }//if

            if (null != transformer.default_properties.
                getProperty(SethTransformer.MAGIC_COOKIE_ELEMENT)) 
            {
                sethcookies.addElement(transformer.default_properties.
                    getProperty(SethTransformer.MAGIC_COOKIE_ELEMENT));
            }//if

            if (null != transformer.default_properties.
                getProperty(SethTransformer.MAGIC_METHOD_ELEMENT)) 
            {
                method = transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_METHOD_ELEMENT);
            }//if

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_URL_ELEMENT)) 
            {
                url = transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_URL_ELEMENT);
            }//if

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_USERNAME_ELEMENT)) 
            {
                username = transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_USERNAME_ELEMENT);
            }//if

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_AUTHSUB_ELEMENT)) 
            {
            
                authsub = transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_AUTHSUB_ELEMENT);
            }//if
                
            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_VOLUME_ELEMENT)) 
            {
                volume = transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_VOLUME_ELEMENT);
            }//if

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_PASSWORD_ELEMENT)) 
            {
                password = transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_PASSWORD_ELEMENT);
            }//if

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_LIMIT_ELEMENT)) 
            {
                limit = transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_LIMIT_ELEMENT);
            }//if

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_USERAGENT_ELEMENT)) 
            {
                useragent = transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_USERAGENT_ELEMENT);
            }//if

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_XMLONLY_ELEMENT)) 
            {
                xmlonly = transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_XMLONLY_ELEMENT).equals("TRUE") ? true : false;
            }//if

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_JSONONLY_ELEMENT)) 
            {
                jsononly = transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_JSONONLY_ELEMENT).equals("TRUE") ? true : false;
            }//if

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_SIFT_ELEMENT)) 
            {
                sift = transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_SIFT_ELEMENT);
            }//if

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_TIMEOUT_ELEMENT)) 
            {
                timeout = Integer.parseInt(transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_TIMEOUT_ELEMENT));
            }//if

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_REDIRECT_LIMIT_ELEMENT)) 
            {
                redirect_limit = Integer.parseInt(transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_REDIRECT_LIMIT_ELEMENT));
            }//if

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_REGEXP_ELEMENT)) 
            {
                regexp = transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_REGEXP_ELEMENT);
            }//if

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_REDIRECT_ELEMENT)) 
            {
                redirect = transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_REDIRECT_ELEMENT).equals("TRUE") ? true : false;
            }//if

            if (null != transformer.
                default_properties.
                getProperty(SethTransformer.MAGIC_DEBUG_ELEMENT)) 
            {
                debug = transformer.
                    default_properties.
                    getProperty(SethTransformer.
                    MAGIC_DEBUG_ELEMENT).equals("TRUE") ? true : false;
            }//if

        } //HTMLRetrieval

        // set up DOM and execute http request
        protected void execute() throws Exception {
            int ret;

            //start with regexp
            if (regexp != null) {
                try {
                    sethRE = new RE(regexp);
                } catch (RESyntaxException reex) {
                    getLogger().debug("[SethTransformer] " +
                        "compiling regular expression  problem " + 
                        reex.toString());
                    regexp = null;
                }//try
            }//if

            if (debug) 
                debugPrint();

            try {
                // Setup an instance of Tidy.
                Tidy tidy = new Tidy();
                tidy.setXmlOut(true);
                tidy.setXHTML(true);
                tidy.setIndentAttributes(true);

                tidy.setShowWarnings(getLogger().isWarnEnabled());
                tidy.setQuiet(!getLogger().isInfoEnabled());
                    
                StringWriter stringWriter = new StringWriter();
                PrintWriter errorWriter = new PrintWriter(stringWriter);
                tidy.setErrout(errorWriter); 

                HttpMethod _httpMethod = workOutHttpMethod(url, username, password, volume);
                URL thisUrl = new URL(url);
                HttpURLConnection _httpURLConnection = new HttpURLConnection(_httpMethod, thisUrl);

                //System.out.println("lm: " + _httpURLConnection.getLastModified());
                Date last_modified = new Date(_httpURLConnection.getLastModified());

                org.w3c.dom.Document doc = null;

                //sift is used for funky syntax
                if (sift != null || jsononly) {
                    String siftResponse = _httpMethod.getResponseBodyAsString();
                    //System.out.println(")-> " + siftResponse);
                            
                    if (jsononly) {
                        transformer.start(RESULT_JSON,attr);
                        transformer.data(siftResponse);
                        transformer.end(RESULT_JSON);
                    } else {
                        Pattern p = Pattern.compile(sift + "\":\"(\\d+)");
                        //Split input with the pattern
                                
                        Matcher matcher = p.matcher(siftResponse);
                        transformer.start(RESULTS_ELEMENT, attr);
                        transformer.start(RESULT_CODE,attr);
                        transformer.data(Integer.toString(result));
                        transformer.end(RESULT_CODE);
                        transformer.start(RESULT_PAGES,attr);
                                
                        while (matcher.find()) {
                            //System.out.print("Start index: " + matcher.start());
                            //System.out.print(" End index: " + matcher.end() + " ");
                            //System.out.println(matcher.group(1));
                                   
                            transformer.start(RESULT_PAGE,attr);
                            transformer.data(matcher.group(1));
                            transformer.end(RESULT_PAGE);
                        }//while
                                
                        transformer.end(RESULT_PAGES);
                        transformer.end(RESULTS_ELEMENT);
                            
                    }//if jsononly

                } else {

                    if (!xmlonly) {
                        doc = tidy.parseDOM(new
                        BufferedInputStream(_httpMethod.getResponseBodyAsStream()), null);
                    } else {
                        StringBuffer contents_value = new StringBuffer();
                        BufferedReader br = new BufferedReader(new 
                            InputStreamReader(_httpMethod.getResponseBodyAsStream()));
                        String readLine;
                        while(((readLine = br.readLine()) != null)) {
                            contents_value.append(readLine);
                        }//while
                
                        doc = loadXMLfrom(contents_value.toString());
                    }//if !xmlonly

                    XMLUtils.stripDuplicateAttributes(doc, null);
                    Element docRoot = doc.getDocumentElement();

                    Cookie[] cookies = _httpClient.getState().getCookies();
                    Header[] responseHeaders = _httpMethod.getResponseHeaders();
                    Header[] requestHeaders = _httpMethod.getRequestHeaders();

                    transformer.start(RESULTS_ELEMENT, attr);
                    transformer.start(RESULT_CODE,attr);
                    transformer.data(Integer.toString(result));
                    transformer.end(RESULT_CODE);
                    transformer.start(URL_ELEMENT, attr);
                    transformer.data(url);
                    transformer.end(URL_ELEMENT);
                    transformer.start(RESPONSE_ELEMENT, attr);

                    for (int i=0; i<responseHeaders.length;i++) {
                        transformer.start("response",
                            nvpAttributes(responseHeaders[i].getName()));
                        transformer.data(responseHeaders[i].getValue());
                        transformer.end("response");
                    }//for

                    //special date
                    transformer.start("response",nvpAttributes("last_modified_check"));
                    transformer.data(last_modified.toString());
                    transformer.end("response");
                    transformer.end(RESPONSE_ELEMENT);

                    transformer.start(REQUEST_ELEMENT, attr);

                    for (int i=0; i<requestHeaders.length;i++) {
                        transformer.start("request",nvpAttributes(requestHeaders[i].getName()));
                        transformer.data(requestHeaders[i].getValue());
                        transformer.end("request");
                    }//for
                            
                    transformer.end(REQUEST_ELEMENT);

                    transformer.start(COOKIES_ELEMENT, attr);
                    for (int i = 0; i < cookies.length; i++) {
                        transformer.start("cookie",cookieAttributes(cookies[i]));
                        transformer.data(cookies[i].getValue());
                        transformer.end("cookie");
                    }//for
                    transformer.end(COOKIES_ELEMENT);

                    transformer.start(CONTENTS_ELEMENT,attr);
                    traverse(doc);
                    transformer.end(CONTENTS_ELEMENT);

                    transformer.end(RESULTS_ELEMENT);
                }//if

                errorWriter.flush();
                errorWriter.close();

                if(getLogger().isWarnEnabled()){
                    getLogger().warn(stringWriter.toString());
                }//if
        
            } catch (Exception e){
                getLogger().error("problem: ", e);
                throw new ProcessingException("Exception in SethTransformer.execute",e);
            }//try
        } //execute

        protected org.w3c.dom.Document loadXMLfrom(String xml)
            throws org.xml.sax.SAXException, java.io.IOException 
        {
            return loadXMLfrom(new java.io.ByteArrayInputStream(xml.getBytes()));
        }//loadXMLfrom

        protected org.w3c.dom.Document loadXMLfrom(java.io.InputStream is) 
            throws org.xml.sax.SAXException, java.io.IOException 
        {
            javax.xml.parsers.DocumentBuilderFactory factory =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            javax.xml.parsers.DocumentBuilder builder = null;

            try {
                builder = factory.newDocumentBuilder();
            } catch (javax.xml.parsers.ParserConfigurationException ex) {
                getLogger().error("problem: ", ex);
            }//try  
                    
            org.w3c.dom.Document doc = builder.parse(is);
            is.close();
                    
            return doc;
        }//loadXMLfrom
  
        protected AttributesImpl nvpAttributes(String theName) 
            throws IOException, SAXException
        {
            AttributesImpl nvpAtts = new AttributesImpl();
            nvpAtts.addAttribute( null,
                "name","name",
                "CDATA",theName);

            return nvpAtts;
        }//nvpAttributes

        protected AttributesImpl cookieAttributes(Cookie theCookie) 
            throws IOException, SAXException
        {
            AttributesImpl cookieAtts = new AttributesImpl();
            cookieAtts.addAttribute( null,
                "name","name",
                "CDATA",theCookie.getName());
            if (theCookie.getDomain() != null)
                cookieAtts.addAttribute( null,
                    "domain","domain",
                    "CDATA",theCookie.getDomain());
            if (theCookie.getPath() != null)
                cookieAtts.addAttribute( null,
                    "path","path",
                    "CDATA",theCookie.getPath());
            if (theCookie.getExpiryDate() != null)
                cookieAtts.addAttribute( null,
                    "date","date",
                    "CDATA",theCookie.getExpiryDate().toString());
            if (theCookie.getSecure() == true)
                cookieAtts.addAttribute( null,
                    "secure","secure",
                    "CDATA","TRUE");

            return cookieAtts;
        }//cookieAttributes

        //this is specific to google
        protected String addVolumeWithAtom(String volumeIdent) {
            StringBuffer xml = new StringBuffer();
            StringWriter stringWriter = new StringWriter();
   
            try {
                XMLStreamWriter xmlStreamWriter = XMLOutputFactory.newInstance().
                    createXMLStreamWriter(stringWriter);
                xmlStreamWriter.writeStartDocument("UTF-8", "1.0");
                xmlStreamWriter.setDefaultNamespace("http://www.w3.org/2005/Atom");
                xmlStreamWriter.writeStartElement("http://www.w3.org/2005/Atom", "entry");
                xmlStreamWriter.writeDefaultNamespace("http://www.w3.org/2005/Atom");
                xmlStreamWriter.writeNamespace("gd", "http://schemas.google.com/g/2005");

                xmlStreamWriter.writeStartElement("http://www.w3.org/2005/Atom", "id");
                xmlStreamWriter.writeCharacters("http://books.google.com/books/feeds/volumes/" + volumeIdent);
                xmlStreamWriter.writeEndElement();
                xmlStreamWriter.writeEndElement();
                xmlStreamWriter.writeEndDocument();
                
                xmlStreamWriter.flush();
                xmlStreamWriter.close();
   
            } catch (XMLStreamException e) {
                e.printStackTrace();
            } catch (FactoryConfigurationError e) {
                e.printStackTrace();
            }//try 

            xml = stringWriter.getBuffer();
            
            return xml.toString();
        }//getAtomRequest

        protected HttpMethod workOutHttpMethod(String url, String username, 
            String password, String volume) 
        {
            String redirectLocation = "";
            String atomAdd = "";

            try {
                Header locationHeader = null;
                URL u = new URL(url);

                //custom ssl to handle self-signed certificates
                Protocol easyhttps = new Protocol("https", new EasySSLProtocolSocketFactory(), 443);
                Protocol.registerProtocol("https", easyhttps);

                _httpClient = new HttpClient();
                HttpState state = new HttpState();

                if (useragent != null) {
                    System.getProperties().
                        setProperty("httpclient.useragent", 
                        useragent);
                }//if


                //should open this up for generator control
                state.setCookiePolicy(CookiePolicy.COMPATIBILITY);

                //how to add your own cookie
                //Cookie mycookie = new Cookie("privcom.gc.ca", "mycookie", "stuff", "/", null, false);
                //state.addCookie(mycookie);

                for (int i=0; i<sethcookies.size(); i++) {
                    Cookie theCookie = (Cookie) sethcookies.elementAt(i);
                    state.addCookie(theCookie);
                }//for

                _httpClient.setState(state);

                // HTTP-Method
                if(method.equals("POST")) {
                    _httpMethod = new PostMethod(u.getPath());      
                    
                    //((PostMethod) _httpMethod).setUseDisk(false);           

                    for (int i=0; i<nvps.size(); i++) {
                        NameValuePair formNVP = (NameValuePair) nvps.
                            elementAt(i);
                        ((PostMethod) _httpMethod).
                            addParameter(formNVP);
                    }//for
                                
                    if (volume != null) {
                        atomAdd = addVolumeWithAtom(volume);
                        RequestEntity requestEntity = new StringRequestEntity(atomAdd, 
                            "application/atom+xml", "UTF-8");
                        
                        ((PostMethod) _httpMethod).
                            setRequestEntity(requestEntity);
                        
                        ((PostMethod) _httpMethod).
                            setRequestHeader(
                                "Content-Length", 
                                Integer.toString(atomAdd.length()));
                    }//if

                } else {

                    _httpMethod = new GetMethod(u.getPath());
                    //((GetMethod) _httpMethod).setUseDisk(false);
                    
                    if (nvps.size() > 0) {
                        String qs = ((HttpMethod) _httpMethod).getQueryString();
                        NameValuePair nvpa[] = new NameValuePair[nvps.size()];
                        ((HttpMethod) _httpMethod).setQueryString((NameValuePair []) 
                            nvps.toArray(nvpa));
                            
                        if (qs != null) {
                            ((HttpMethod) _httpMethod).
                                setQueryString(qs + "&" + 
                                ((HttpMethod) _httpMethod).
                                getQueryString());
                        }//if qs
                    
                    }//if nvps
                    
                }//if method

                //zero is no timeout
                if (timeout > 0)
                    _httpClient.setTimeout(timeout * 1000);
            
                if (redirect) {
                    if (method.equals("GET"))
                        ((HttpMethod) _httpMethod).setFollowRedirects(redirect);
                        
                    //if we had to do redirects for a post, this would be necessary
                    /*
                    if (method.equals("POST")) {
                        URI redirectLocation = new URI(
                            ((HttpMethod) _httpMethod).getURI(),
                            ((HttpMethod) _httpMethod).getResponseHeader("location").
                            getValue());
                            
                    }
                    */
                        
                }//if redirect

                // HTTPSession
                //_httpClient.startSession(u);
                HostConfiguration hostConfig = _httpClient.getHostConfiguration();
                hostConfig.setHost(u.getHost(),u.getPort(),u.getProtocol());

                /* - would we ever set these?
                    for(int i = 0; i < this.header.size(); i++) {
                        ((HttpMethod) _httpMethod).setRequestHeader( 
                        (Header) this.header.elementAt(i));
                    }
                */

                // value for "accept-encoding" must be empty
                ((HttpMethod) _httpMethod).
                    setRequestHeader("accept-encoding", "");

                if (authsub != null) {
                    ((HttpMethod) _httpMethod).
                        setRequestHeader(
                        "Content-Type", 
                        "application/atom+xml");
                            
                    //specific to google books authentication
                    Header authorization = new Header("Authorization", "GoogleLogin auth=" + authsub);
                    ((HttpMethod) _httpMethod).setRequestHeader(authorization);
                }//if

                if (username != null && password != null) {
                    List authPrefs =  new ArrayList(2);
                    authPrefs.add(AuthPolicy.DIGEST );
                    authPrefs.add(AuthPolicy.BASIC);
                    _httpClient.getParams().setParameter (AuthPolicy.AUTH_SCHEME_PRIORITY, authPrefs);
                    _httpClient.getParams().setAuthenticationPreemptive(true);
                    Credentials defaultcreds = new UsernamePasswordCredentials(username, password); 
                    //_httpClient.getState().setCredentials(new AuthScope( u.getHost(), 443, AuthScope.ANY_REALM), defaultcreds);
                    _httpClient.getState().setCredentials(null, u.getHost(), defaultcreds);
                }//if

                try {
                    result = _httpClient.executeMethod(_httpMethod);                    
                } catch (Exception ex) {
                    System.out.println("exception to execute: " + ex.toString());
                }//try

                int num_redirects = 0;

                while (result == HttpStatus.SC_MOVED_TEMPORARILY &&
                    num_redirects++ < redirect_limit) 
                {
                    //will need to make this a parameter at some point
                    locationHeader = 
                        ((HttpMethod) _httpMethod).
                        getResponseHeader("location");
                    
                    if (locationHeader != null) {
                        redirectLocation = 
                            locationHeader.getValue();
                                
                        if (method.equals("GET")) {
                            _httpMethod = new GetMethod(redirectLocation);
                        } else {
                            //again, assuming a redirect is always a GET
                            //if not, we would need something like this
                            _httpMethod = new PostMethod(redirectLocation);
                        }//if
                            
                        _httpMethod = new GetMethod(redirectLocation);
                        result = _httpClient.executeMethod(_httpMethod);                    
                    }//if
                }//while

                Cookie[] cookies = _httpClient.getState().getCookies();

                if (username != null && password != null)
                    _httpMethod.setDoAuthentication( true );

                return _httpMethod;
            } catch (Exception e){
                getLogger().error("problem: ", e);
            }//try

            return null;
        }//workOutHttpMethod

        //  Traverse DOM Tree.  Print out Element Names
        protected void traverse (Node node)
            throws IOException, SAXException 
        {
            String name = "";
            String value = "";
            int numChildren = 0;

            int type = node.getNodeType();
            NodeList children = node.getChildNodes();

            if (children != null)
                numChildren = children.getLength();

            getLogger().debug("[SethTransformer] node type: " + type);

            if (type == Node.ELEMENT_NODE) {
                name =
                    node.getNodeName().trim();
                
                if (!checkLimitTags(name))
                    transformer.start(name, copyAttributes(node));
            }//if
            if (type == Node.TEXT_NODE) {
                value =
                    node.getNodeValue().trim();
                if (textBucket.length() > 0)
                    textBucket.append(" ");
                textBucket.append(value);
            }//if
            if (children != null) {
                for (int i=0; i< numChildren; i++) 
                    traverse (children.item(i));  
            }//if
                                
            if (type == Node.ELEMENT_NODE) {
                if (regexp != null && textBucket.length() > 0) {
                    try {
                        String newText = 
                            textBucket.toString();
                
                        if (sethRE.match(newText)) {
                            getLogger().debug("[SethTransformer] regexp: " + regexp +
                                " matches on " + newText);
                            /* RE matches ok, but doesn't extract properly, may not need */ 
                            /*
                                System.out.println("1> " + sethRE.getParenStart(0));
                                System.out.println("2> " + sethRE.getParenStart(1));
                                System.out.println("3> " + sethRE.getParenEnd(0));
                                System.out.println("4> " + sethRE.getParenEnd(1));
                                System.out.println("5> " + sethRE.getParen(0));
                                System.out.println("6> " + sethRE.getParen(1));
                            */

                            transformer.start(REGEXP_ELEMENT,attr);
                            transformer.data(newText);
                            transformer.end(REGEXP_ELEMENT);
                            textBucket.setLength(0);
                        }//if sethRE
                    } catch (Exception reex) {
                        System.out.println("matching regular expression  problem " + reex.toString());
                        regexp = null;
                    }//try
                }//if regexp

                if (textBucket.length() > 0) {
                    if (!checkLimitTags(name))
                        transformer.data(textBucket.toString());
                    textBucket.setLength(0);
                }//if

                if (!checkLimitTags(name))
                    transformer.end(name);
            }//if
        }//traverse

        protected boolean checkLimitTags(String currentTag) {
            if (limit != null) {
                String thisLimit = "," + limit + ",";
                int limitNum = thisLimit.indexOf("," + currentTag.trim().toUpperCase() + ",");

                if (limitNum == -1 )
                    return true;
            }//if

            return false;
        }//checkLimitTags

        protected AttributesImpl copyAttributes(Node currentNode) 
            throws IOException, SAXException
        {
            AttributesImpl currentAtts = new AttributesImpl();
            NamedNodeMap map = currentNode.getAttributes();
            currentAtts.clear();
            
            for (int i = map.getLength() - 1; i >= 0; i--) {
                Attr att = (Attr) map.item(i);
                /*
                currentAtts.addAttribute( att.getNamespaceURI(),
                    att.getLocalName(), att.getName(),
                    "CDATA", att.getValue());
                */
                currentAtts.addAttribute(null,att.getName(), att.getName(),
                    "CDATA", att.getValue());
            }//for
    
            return currentAtts;
        }//copyAttributes

        //show every element if working in DEBUG mode
        protected void debugPrint() {
            transformer.getLogger().debug("[SethTransformer] retrieval_index: " + retrieval_index);
            transformer.getLogger().debug("[SethTransformer] # of nvps: " + nvps.size());
            transformer.getLogger().debug("[SethTransformer] # of cookies: " + sethcookies.size());
            transformer.getLogger().debug("[SethTransformer] url: " + url);
            transformer.getLogger().debug("[SethTransformer] limit: " + limit);
            transformer.getLogger().debug("[SethTransformer] redirect_limit: " + redirect_limit);
            transformer.getLogger().debug("[SethTransformer] useragent: " + useragent);
            transformer.getLogger().debug("[SethTransformer] xmlonly: " + xmlonly);
            transformer.getLogger().debug("[SethTransformer] jsononly: " + jsononly);
            transformer.getLogger().debug("[SethTransformer] sift: " + sift);
            transformer.getLogger().debug("[SethTransformer] timeout: " + timeout);
            transformer.getLogger().debug("[SethTransformer] redirect: " + redirect);
            transformer.getLogger().debug("[SethTransformer] regexp: " + regexp);
        }//debugPrint

    }//HTMLRetrieval
}//SethTransformer
