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
import br.edu.utfpr.md.restapi.dao.CategoryDAO;
import br.edu.utfpr.md.restapi.dao.PessoaDAO;
import br.edu.utfpr.md.restapi.model.Category;
import br.edu.utfpr.md.restapi.model.Document;
import br.edu.utfpr.md.restapi.model.Pessoa;
import br.edu.utfpr.md.restapi.security.Autenticado;
import java.util.List;
import javax.inject.Inject;

@Controller
@Path("/category")
public class CategoryResource {
    
    @Inject
    private CategoryDAO catdao;

    @Inject
    private Result result;

    @Post("")
    @Consumes("application/json")
    public void save(Category cat) {
        try {
            catdao.save(cat);
            result.use(Results.json())
                    .withoutRoot()
                    .from(cat)
                    .serialize();
        } catch (Exception ex) {
            result.use(Results.http()).setStatusCode(400);
            ex.printStackTrace();
        }
    }

    @Put("")
    @Consumes("application/json")
    public void update(Category cat) {
        catdao.update(cat);
        result.use(Results.json())
                .withoutRoot()
                .from(cat)
                .serialize();
    }

    @Delete("/{id}")
    public void delete(int id) {
        Category cat = catdao.getById(id);

        if (cat == null) {
            result.use(Results.status()).notFound();
        } else {
            catdao.delete(cat);
            // result.use(Results.status()).ok(); ou
            result.use(Results.nothing());
        }

    }

    @Get("/{id}")
    public void getOne(int id) {
        Category cat = catdao.getById(id);
        result.use(Results.json())
                .withoutRoot()
                .from(cat)
                .serialize();
    }

    @Autenticado
    @Get(value = {"", "/"})
    public void getAll() {
        List<Category> list = catdao.findAll();

        result.use(Results.json())
                .withoutRoot()
                .from(list)
                .serialize();
    }
    
    @Autenticado
    @Get(value = {"/person/{id}"})
    public void getAllByUser(int id) {
        List<Category> list = catdao.findAllbyUser(id);

        result.use(Results.json())
                .withoutRoot()
                .from(list)
                .serialize();
    }
    
}
