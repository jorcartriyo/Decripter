/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.rcibanque.common.util;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 *
 * @author Jorge
 */
public class Decripter {

    /**
     * @param args the command line arguments
     */
 
    public static void main(String[] args ) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException{
        
       HashPassword.hash("dddddd", "ass", 200, 208);
       
     
        
        
    }
    
}
