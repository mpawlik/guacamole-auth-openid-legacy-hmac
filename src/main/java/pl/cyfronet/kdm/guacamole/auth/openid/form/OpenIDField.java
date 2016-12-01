package pl.cyfronet.kdm.guacamole.auth.openid.form;

import org.glyptodon.guacamole.form.Field;

public class OpenIDField extends Field {

    public static final String PARAMETER_NAME = "id_token";
    private final String authorizationURI;

    public String getAuthorizationURI() {
        return authorizationURI;
    }


    public OpenIDField(String authorizationEndpoint) {
        super(PARAMETER_NAME, "GUAC_OPENID_TOKEN");
        this.authorizationURI = authorizationEndpoint;
    }
}
