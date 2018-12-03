package br.edu.utfpr.md.restapi.resource;

import br.com.caelum.vraptor.Consumes;
import br.com.caelum.vraptor.Controller;
import br.com.caelum.vraptor.Post;
import br.com.caelum.vraptor.Result;
import br.com.caelum.vraptor.view.Results;
import br.edu.utfpr.md.restapi.dao.PessoaDAO;
import br.edu.utfpr.md.restapi.security.JWTUtil;
import com.auth0.jwt.JWTVerifyException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.inject.Inject;

@Controller
public class AuthResource {

    @Inject
    private Result result;
    
    @Inject
    PessoaDAO pessoadao;
    
    @Post("/login")
    @Consumes("application/json")
    public void login(String email, String senha) {
        // Verificando se as credenciais são válidas
        String token = null;
        if(pessoadao.finduser(email, senha)!=null) {
            long UserLoggedId = pessoadao.finduser(email, senha).getId();
            token = JWTUtil.createToken( UserLoggedId );
            
            result.use(Results.status()).header("Content-type", "text/plain");
            result.use(Results.status()).ok();
            result.use(Results.http()).body(token);
            
        }
        else {
            result.use(Results.status()).notFound();
            result.use(Results.http()).body("");
        }
        Map<String, Object> claims = null;
        try {
            try {
                claims = JWTUtil.decode(token);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(AuthResource.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(AuthResource.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SignatureException ex) {
                Logger.getLogger(AuthResource.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(AuthResource.class.getName()).log(Level.SEVERE, null, ex);
            }

            Integer userId = (Integer) claims.get("user");
            System.err.println("userid" + userId);
            System.out.println(userId);
            
        } catch (IllegalStateException | JWTVerifyException e) {
            result.use(Results.http()).setStatusCode(401);
            result.use(Results.json()).from(e.getMessage(), "msg").serialize();
        }
    }
}
