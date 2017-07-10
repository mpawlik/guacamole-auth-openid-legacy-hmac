package pl.cyfronet.kdm.guacamole.auth.openid;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.net.auth.*;
import org.apache.guacamole.net.auth.credentials.CredentialsInfo;
import org.apache.guacamole.net.auth.credentials.GuacamoleInvalidCredentialsException;
import org.apache.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import org.apache.guacamole.net.auth.simple.SimpleConnection;
import org.apache.guacamole.net.auth.simple.SimpleConnectionDirectory;
import org.apache.guacamole.net.auth.simple.SimpleUserContext;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.apache.http.auth.InvalidCredentialsException;
import org.openid4java.OpenIDException;
import org.openid4java.association.AssociationException;
import org.openid4java.association.AssociationSessionType;
import org.openid4java.consumer.*;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.MessageException;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.FetchRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pl.cyfronet.kdm.guacamole.auth.openid.form.OpenIDField;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

public class OpenIDAuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(OpenIDAuthenticationService.class);


    private static ConsumerManager consumerManager;
    private final String openIdEndpoint;
    private final String returnToUrl;
    private final String realm;
    private SignatureVerifier signatureVerifier;

    public static final String SIGNATURE_PARAM = "signature";
    public static final String ID_PARAM = "id";
    public static final String TIMESTAMP_PARAM = "timestamp";
    public static final String PARAM_PREFIX = "guac.";

    public static final String SESSION_CONFIG_STORE = "guacConfig";

    public static final long TEN_MINUTES = 10 * 60 * 1000;
    private long timestampAgeLimit = TEN_MINUTES; // 10 minutes

    private String defaultProtocol = "rdp";

    private static final List<String> SIGNED_PARAMETERS = new ArrayList<String>() {{
        add("username");
        add("password");
        add("hostname");
        add("port");
    }};

    static {
        logger.debug("Creating new ConsumerManager");
        consumerManager = new ConsumerManager();
        consumerManager.setAssociations(new InMemoryConsumerAssociationStore());
        consumerManager.setNonceVerifier(new InMemoryNonceVerifier(5000));
        consumerManager.setMinAssocSessEnc(AssociationSessionType.DH_SHA256);
    }

    public OpenIDAuthenticationService() throws GuacamoleException {

        //initialize parameters from properties
        Environment environment = new LocalEnvironment();

        openIdEndpoint = environment.getRequiredProperty(OpenIDAuthenticationProperties.OPENID_ENDPOINT);
        logger.debug("Setting openIdEndpoint to: {}", openIdEndpoint);
        returnToUrl = environment.getRequiredProperty(OpenIDAuthenticationProperties.OPENID_RETURNTOURL);
        logger.debug("Setting returnToUrl to: {}", returnToUrl);
        realm = environment.getRequiredProperty(OpenIDAuthenticationProperties.OPENID_REALM);
        logger.debug("Setting realm to: {}", realm);

        String secretKey = environment.getRequiredProperty(OpenIDAuthenticationProperties.SECRET_KEY);
        logger.debug("Setting secret key to: {}", secretKey);
        signatureVerifier = new SignatureVerifier(secretKey);
        logger.debug("Initialized signature verifier");
    }

    public AuthenticatedUser authenticateUser(final AuthenticationProvider authenticationProvider, final Credentials credentials) throws GuacamoleException {
        logger.debug("Service authenticateUser()");
        //put openid code here, check for proper request if it's invalid throw exception

        HttpServletRequest httpServletRequest = credentials.getRequest();

        logger.debug("queryURL: {}", httpServletRequest.getRequestURI());
        logger.debug("queryString: {}", httpServletRequest.getQueryString());
        for (Enumeration e = httpServletRequest.getAttributeNames(); e.hasMoreElements(); ) {
            logger.debug("attribute: {}", e.nextElement());
        }
        logger.debug("parameterCount: {}", httpServletRequest.getParameterMap().keySet().size());

        for (Object keyObj : httpServletRequest.getParameterMap().keySet()) {
            String key = (String) keyObj;
            logger.debug("key: {}", key);
        }
        if (httpServletRequest.getParameter("openid.identity") != null) {
            logger.debug("authenticateUser(): handle reposnse");
            try {
                //handle incoming openid response

                ParameterList response = new ParameterList(httpServletRequest.getParameterMap());
                DiscoveryInformation discovered = (DiscoveryInformation) httpServletRequest.getSession().getAttribute("openid-disc");

                StringBuffer receivingURL = new StringBuffer(returnToUrl);
                String queryString = httpServletRequest.getQueryString();
                if (queryString != null && queryString.length() > 0)
                    receivingURL.append("?").append(httpServletRequest.getQueryString());

                VerificationResult verification = consumerManager.verify(receivingURL.toString(), response, discovered);

                Identifier verified = verification.getVerifiedId();
                logger.debug("finished with verification");
                if (verified != null) {
                    //success!
                    //create new user information
                    logger.debug("success");
                    final String userIdentifier = verified.getIdentifier();
                    credentials.setUsername(userIdentifier);
                    return new AbstractAuthenticatedUser() {
                        public AuthenticationProvider getAuthenticationProvider() {
                            return authenticationProvider;
                        }

                        public Credentials getCredentials() {
                            return credentials;
                        }
                    };
                }
            } catch (OpenIDException e) {
                e.printStackTrace();
            }

        } else {
            //parse HMAC, new request should have it
            GuacamoleConfiguration config = getGuacamoleConfiguration(httpServletRequest);
            if (config == null) {
                logger.info("Invalid or missing HMAC credentials!");
                return null;
            }

            logger.info("generated configuration: {}", config);

            //save configuration to session store
            httpServletRequest.getSession().setAttribute(SESSION_CONFIG_STORE, config);

            //place a request for new openid authentication action
            logger.debug("authenticateUser(): place auth request");
            List discoveries = null;
            try {
                discoveries = consumerManager.discover(openIdEndpoint);
                DiscoveryInformation discovered = consumerManager.associate(discoveries);

                httpServletRequest.getSession().setAttribute("openid-disc", discovered);

                AuthRequest authReq = consumerManager.authenticate(discovered, returnToUrl);
                authReq.setRealm(realm);

                String destinationUrl = authReq.getDestinationUrl(true);
                logger.debug("destinationURL: {}", destinationUrl);
                throw new GuacamoleInvalidCredentialsException("Invalid login",
                        new CredentialsInfo(Arrays.asList(new Field[]{
                                new OpenIDField(
                                        destinationUrl
                                )
                        }))
                );
            } catch (OpenIDException e) {
                e.printStackTrace();
            }

        }
        return null;
    }

    public UserContext updateUserContext(UserContext context, AuthenticatedUser authenticatedUser) throws GuacamoleException {
        Credentials credentials = authenticatedUser.getCredentials();
        HttpServletRequest request = credentials.getRequest();

        //retrieve guacamole session parameters from session vars
        GuacamoleConfiguration config = (GuacamoleConfiguration) request.getSession().getAttribute(SESSION_CONFIG_STORE);
        if (config == null) {
            logger.info("Invalid configuration stored in session!");
            return null;
        }

        String id = config.getParameter("id");
        SimpleConnectionDirectory connections = (SimpleConnectionDirectory) context.getConnectionDirectory();
        SimpleConnection connection = new SimpleConnection(id, id, config);
        connection.setParentIdentifier(context.getRootConnectionGroup().getIdentifier());
        connections.putConnection(connection);

        return context;
    }

    public UserContext getUserContext(AuthenticationProvider authenticationProvider, AuthenticatedUser authenticatedUser) throws GuacamoleException {
        Credentials credentials = authenticatedUser.getCredentials();
        HttpServletRequest request = credentials.getRequest();
        GuacamoleConfiguration config = (GuacamoleConfiguration) request.getSession().getAttribute(SESSION_CONFIG_STORE);

        if (config == null) {
            logger.info("Invalid configuration stored in session!");
            return null;
        }
        HashMap<String, GuacamoleConfiguration> configs = new HashMap<String, GuacamoleConfiguration>();
        configs.put(config.getParameter("id"), config);
        return new SimpleUserContext(authenticationProvider, authenticatedUser.getIdentifier(), configs);
    }

    private GuacamoleConfiguration getGuacamoleConfiguration(HttpServletRequest request) throws GuacamoleException {
        String signature = request.getParameter(SIGNATURE_PARAM);

        logger.debug("Get hmac signature: {}", signature);

        if (signature == null) {
            return null;
        }
        signature = signature.replace(' ', '+');

        String timestamp = request.getParameter(TIMESTAMP_PARAM);
        if (!checkTimestamp(timestamp)) {
            return null;
        }

        GuacamoleConfiguration config = parseConfigParams(request);

        // Hostname is required!
        if (config.getParameter("hostname") == null) {
            return null;
        }

        // Protocol is required!
        if (config.getProtocol() == null) {
            return null;
        }

        StringBuilder message = new StringBuilder(timestamp)
                .append(config.getProtocol());

        for (String name : SIGNED_PARAMETERS) {
            String value = config.getParameter(name);
            if (value == null) {
                continue;
            }
            message.append(name);
            message.append(value);
        }

        logger.debug("Get hmac message: {}", message.toString());

        if (!signatureVerifier.verifySignature(signature, message.toString())) {
            return null;
        }
        //is this even needed? problalby yes, but not given by the user
        String id = request.getParameter(ID_PARAM);
        if (id == null) {
            id = "DEFAULT";
        } else {
            // This should really use BasicGuacamoleTunnelServlet's IdentfierType, but it is private!
            // Currently, the only prefixes are both 2 characters in length, but this could become invalid at some point.
            // see: guacamole-client@a0f5ccb:guacamole/src/main/java/org/glyptodon/guacamole/net/basic/BasicGuacamoleTunnelServlet.java:244-252
            id = id.substring(2);
        }
        // This isn't normally part of the config, but it makes it much easier to return a single object
        config.setParameter("id", id);
        return config;
    }

    private GuacamoleConfiguration parseConfigParams(HttpServletRequest request) {
        GuacamoleConfiguration config = new GuacamoleConfiguration();

        Map<String, String[]> params = request.getParameterMap();

        for (String name : params.keySet()) {
            String value = request.getParameter(name);
            if (!name.startsWith(PARAM_PREFIX) || value == null || value.length() == 0) {
                continue;
            } else if (name.equals(PARAM_PREFIX + "protocol")) {
                config.setProtocol(request.getParameter(name));
            } else {
                config.setParameter(name.substring(PARAM_PREFIX.length()), request.getParameter(name));
            }
        }

        if (config.getProtocol() == null) config.setProtocol(defaultProtocol);

        return config;
    }


    private boolean checkTimestamp(String ts) {
        if (timestampAgeLimit == 0) {
            return true;
        }

        if (ts == null) {
            return false;
        }
        long timestamp = Long.parseLong(ts, 10);
        long now = System.currentTimeMillis();
        return timestamp + timestampAgeLimit > now;
    }


}
