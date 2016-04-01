package com.btmatthews.sso.demo.controller;

import com.btmatthews.sso.demo.security.SSOUserDetailsImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class PageController {

    private static final Logger LOGGER = LoggerFactory.getLogger(PageController.class);

    @RequestMapping("/")
    public String showDefaultPage() {
        LOGGER.info("Displaying index.hml");
        return "index";
    }

    @RequestMapping("/page/{page}.html")
    public String showPage(@PathVariable("page") final String page, @AuthenticationPrincipal SSOUserDetailsImpl user, final Model model) {
        LOGGER.info("Displaying " + page + ".html for user " + user.getUsername());
        model.addAttribute("principal", user);
        return page;
    }
}
