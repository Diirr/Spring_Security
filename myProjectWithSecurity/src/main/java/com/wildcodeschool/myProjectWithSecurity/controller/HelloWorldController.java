package com.wildcodeschool.myProjectWithSecurity.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {
	String word = "";

    @GetMapping("/")
    public String hello() {
        return "Welcome to the SHIELD";
    }

    @GetMapping("/avengers/assemble")
    public String avengers() {
    return "Avengers.....Assemble";
}

    @GetMapping("/secret-bases")
    public String[] secret() {
	    String[] bases = {"Biarritz","Bordeaux","La Loupe", "Lille","Lyon","Marseille","Nantes","Orleans","Paris","Reims","Strasbourg","Toulouse","Tours","Amstderdam","Barcelone","Berlin","Bruxelles","Bucarest","Budapest","Dublin","Lisbonne","Londres","Madrdid","Milan"};

	return bases;
    }
	
}
