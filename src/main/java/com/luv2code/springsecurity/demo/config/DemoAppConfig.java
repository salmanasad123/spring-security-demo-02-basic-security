package com.luv2code.springsecurity.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

// this is our configuration class and this replaces our spring-mvc-demo-servlet.xml
// provide support for annotation-driven
// packages to scan took look for controllers and support classes replaces @Component-scan in xml
@Configuration
@EnableWebMvc
@ComponentScan(basePackages = "com.luv2code.springsecurity.demo")
public class DemoAppConfig {

    // define a bean for view resolver, by this view resolve spring will know about the directory
    // to look for views in which directory it should look for views
    @Bean
    public ViewResolver viewResolver(){

        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        // set pre-fix on view resolver
        viewResolver.setPrefix("/WEB-INF/view/");
        // set suffix on view resolver
        viewResolver.setSuffix(".jsp");
        return viewResolver;
    }
}
