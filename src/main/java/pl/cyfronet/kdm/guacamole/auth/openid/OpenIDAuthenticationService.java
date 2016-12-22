package pl.cyfronet.kdm.guacamole.auth.openid;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.form.Field;
import org.glyptodon.guacamole.net.auth.AuthenticatedUser;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.net.auth.credentials.CredentialsInfo;
import org.glyptodon.guacamole.net.auth.credentials.GuacamoleInvalidCredentialsException;
import org.openid4java.association.AssociationSessionType;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.InMemoryConsumerAssociationStore;
import org.openid4java.consumer.InMemoryNonceVerifier;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.MessageException;
import org.openid4java.message.ax.FetchRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pl.cyfronet.kdm.guacamole.auth.openid.form.OpenIDField;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;

public class OpenIDAuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(OpenIDAuthenticationService.class);
    private static final String CONSUMER_MANAGER = "openid_consumer_manager";
    private static final String returnToUrl = "https://viz.pro.cyfronet.pl/screen/";


    private static ConsumerManager consumerManager;
    private static DiscoveryInformation discovered;


    public OpenIDAuthenticationService(HttpServletRequest request) {

        logger.debug("create new ConsumerManager");
        this.consumerManager = new ConsumerManager();
        consumerManager.setAssociations(new InMemoryConsumerAssociationStore());
        consumerManager.setNonceVerifier(new InMemoryNonceVerifier(5000));
        consumerManager.setMinAssocSessEnc(AssociationSessionType.DH_SHA256);
    }

    public AuthenticatedUser authenticateUser(Credentials credentials) throws GuacamoleException {
        logger.debug("authenticateUser()");
        //put openid code here, check for proper request if it's invalid throw exception
        List discoveries = null;
        try {
            discoveries = consumerManager.discover("https://openid.plgrid.pl/gateway");
            discovered = consumerManager.associate(discoveries);

            FetchRequest fetch = FetchRequest.createFetchRequest();
            fetch.addAttribute("email", "http://schema.openid.net/contact/email", true);

            AuthRequest authReq = consumerManager.authenticate(discovered, returnToUrl);
            authReq.addExtension(fetch);

            String destinationUrl = authReq.getDestinationUrl(true);
            logger.debug("destinationURL: {}", destinationUrl);
            throw new GuacamoleInvalidCredentialsException("Invalid login",
                    new CredentialsInfo(Arrays.asList(new Field[]{
                            new OpenIDField(
                                    destinationUrl
                            )
                    }))
            );
        } catch (DiscoveryException e) {
            e.printStackTrace();
        } catch (ConsumerException e) {
            e.printStackTrace();
        } catch (MessageException e) {
            e.printStackTrace();
        }

        return null;
    }

}
