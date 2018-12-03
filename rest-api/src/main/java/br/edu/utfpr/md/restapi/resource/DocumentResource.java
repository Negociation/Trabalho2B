/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.edu.utfpr.md.restapi.resource;

import br.com.caelum.vraptor.Consumes;
import br.com.caelum.vraptor.Controller;
import br.com.caelum.vraptor.Delete;
import br.com.caelum.vraptor.Get;
import br.com.caelum.vraptor.Path;
import br.com.caelum.vraptor.Post;
import br.com.caelum.vraptor.Put;
import br.com.caelum.vraptor.Result;
import br.com.caelum.vraptor.view.Results;
import br.edu.utfpr.md.restapi.dao.DocumentDAO;
import br.edu.utfpr.md.restapi.dao.PessoaDAO;
import br.edu.utfpr.md.restapi.model.Document;
import br.edu.utfpr.md.restapi.model.Pessoa;
import br.edu.utfpr.md.restapi.security.Autenticado;
import java.util.List;
import javax.inject.Inject;

@Controller
@Path("/document")
public class DocumentResource {
      @Inject
    private DocumentDAO documentoDAO;

    @Inject
    private Result result;
    
    @Post("")
    @Consumes("application/json")
    public void save(Document documento) {
    try {
            documentoDAO.save(documento);
            result.use(Results.json())
                    .withoutRoot()
                    .from(documento)
                    .serialize();
        } catch (Exception ex) {
            result.use(Results.http()).setStatusCode(400);
            ex.printStackTrace();
        }
    }
    
    @Put("")
    @Consumes("application/json")
    public void update(Document documento) {
        documentoDAO.update(documento);
        result.use(Results.json())
                .withoutRoot()
                .from(documento)
                .serialize();
    }

    @Delete("/{id}")
    public void delete(int id) {
        Document p = documentoDAO.getById(id);

        if (p == null) {
            result.use(Results.status()).notFound();
        } else {
            documentoDAO.delete(p);
            // result.use(Results.status()).ok(); ou
            result.use(Results.nothing());
        }

    }

    @Get("/{id}")
    public void getOne(int id) {
        Document documento = documentoDAO.getById(id);
        result.use(Results.json())
                .withoutRoot()
                .from(documento)
                .serialize();
    }

    @Autenticado
    @Get(value = {"", "/"})
    public void getAll() {
        List<Document> list = documentoDAO.findAll();

        result.use(Results.json())
                .withoutRoot()
                .from(list)
                .serialize();
    }
    
        @Autenticado
    @Get(value = {"/document/person/{id}"})
    public void getAllByUser(int id) {
        List<Document> list = documentoDAO.findAllbyUser(id);

        result.use(Results.json())
                .withoutRoot()
                .from(list)
                .serialize();
    }
    
        
        @Autenticado
    @Get(value = {"/document/person/{id}"})
    public void getAllByCategory(int id) {
        List<Document> list = documentoDAO.findAllbyCategory(id);

        result.use(Results.json())
                .withoutRoot()
                .from(list)
                .serialize();
    }
}
