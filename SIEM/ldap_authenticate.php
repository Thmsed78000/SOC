<?php

session_start() ;

// Configuration LDAP

$1dap_server = "1dap://10.241.239.15"; // IP du serveur LDAP

$1dap_port = 389; // Port LDAP

// $1dap_base_dn = "cn=Administrateurs, dc=SOC, dc=IT"; // DN o@ se trouvent les utilisateurs
$1dap_base_dn = "dc=SOC, dc=IT";
$1dap_user_attr = "cn"; // Utilisation de "cn" pour l'identifiant utilisateur

//ROcupOration des informations du formulaire

$username = $_POST['username' ] ?? '';

$password = $_POST['password' ] ?? '' ;

// V@rification des champs vides

if (empty($username) || empty($password)) {

    $_SESSION['error'] = "Veuillez fournir un nom d'utilisateur et un mot de passe.";

    header ( 'Location: login.html'); // Redirige vers la page d'authentification

    exit;

}

// Connexion au serveur LDAP

$1dap_conn = ldap_connect($1dap_server, $1dap_port);

if (!$1dap_conn) {

    $_SESSION['error'] = "Erreur : Impossible de se connecter au serveur LDAP.";
    
    header ('Location: login.html' ) ; // Redirige vers la page d'authentification
    
    exit;

}
    
// Configuration des options LDAP
    
ldap_set_option($1dap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
    
ldap_set_option($1dap_conn, LDAP_OPT_REFERRALS, 0) ;
    
//Construction du DN de l'utilisateur
    
$user_dn = "cn=$username, cn=Administrateurs, dc=SOC, dc=IT";
    
// Tenter la connexion LDAP (bind)
    
if (@ldap_bind($1dap_conn, $user_dn, $password) ) {
    
    // Authentification rOussie
    
    $_SESSION[ 'authenticated'] = true;
    
    $_SESSION['username' ] = $username;

    ldap_close($1dap_conn) ; // Fermer la connexion LDAP

    header ('Location: index.html' ) ; // Redirige vers la page d'accueil
    
    exit;
    
}else {
    
    //Qchec de l'authentification
    
    $_SESSION['error' ] = "Nom d'utilisateur ou mot de passe incorrect.";
    
    ldap_close($1dap_conn); // Fermer la connexion LDAP
    
    header ( 'Location: login.html'); // Redirige vers la page d'authentification

}