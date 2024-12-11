<?php
/**
 * Plugin Name: WP Secure Auth
 * Description: Basic Authentication handler for the JSON API, used for development and debugging purposes
 * Author: Gabriel Magallanes
 * Author URI: 
 * Version: 0.4
 * Plugin URI:
 */

function custom_rest_authentication_errors($result) {
    if ( ! empty( $result ) ) {
        return $result;
    }

    $no_auth_endpoints = array(
        '/wp-json/produ/v1/load-more',
    );

    $request_uri = $_SERVER['REQUEST_URI'];
    foreach ( $no_auth_endpoints as $endpoint ) {
        if ( strpos( $request_uri, $endpoint ) !== false ) {
            return true;
        }
    }

    if ( ! is_user_logged_in() ) {
        return new WP_Error('rest_not_logged_in', 'You are not currently logged in.', array('status' => 401));
    }

    return $result;
}
add_filter('rest_authentication_errors', 'custom_rest_authentication_errors');

function json_basic_auth_handler( $user ) {
    global $wp_json_basic_auth_error;

    $wp_json_basic_auth_error = null;

    if ( ! empty( $user ) ) {
        return $user;
    }

    if ( ! isset( $_SERVER['PHP_AUTH_USER'] ) ) {
        return $user;
    }

    $username = $_SERVER['PHP_AUTH_USER'];
    $password = $_SERVER['PHP_AUTH_PW'];

    remove_filter( 'determine_current_user', 'json_basic_auth_handler', 20 );

    $user = wp_authenticate( $username, $password );

    add_filter( 'determine_current_user', 'json_basic_auth_handler', 20 );

    if ( is_wp_error( $user ) ) {
        $wp_json_basic_auth_error = $user;
        return null;
    }

    $wp_json_basic_auth_error = true;

    return $user->ID;
}
add_filter( 'determine_current_user', 'json_basic_auth_handler', 20 );

function my_custom_permission_callback( $request ) {
    if ( $request->get_route() === '/produ/v1/load-more' ) {
        return true;
    }
    return current_user_can( 'edit_others_posts' );
}

// // Registrar las rutas
// function my_register_routes() {
//     register_rest_route( 'produ/v1', '/load-more', array(
//         'methods'  => 'GET',
//         'callback' => 'my_custom_endpoint_callback',
//         'permission_callback' => '__return_true', // Callback que siempre retorna true
//     ) );

//     // Registrar otras rutas que requieren autenticación
//     register_rest_route( 'my-plugin/v1', '/my-secure-endpoint', array(
//         'methods'  => 'GET',
//         'callback' => 'my_secure_endpoint_callback',
//         'permission_callback' => 'my_custom_permission_callback',
//     ) );

//     register_rest_route('produ/v1', '/load-more-posts', array(
//         'methods' => 'GET',
//         'callback' => 'my_load_more_posts_callback',
//         'permission_callback' => '__return_true', // El endpoint no requiere autenticacion
//     ));
// }
// add_action( 'rest_api_init', 'my_register_routes' );

// function my_custom_endpoint_callback( $request ) {
//     return new WP_REST_Response( array( 'message' => 'Hello, World!' ), 200 );
// }

// function my_secure_endpoint_callback( $request ) {
//     return new WP_REST_Response( array( 'message' => 'This is a secure endpoint!' ), 200 );
// }

// function my_load_more_posts_callback( $request ) {
//     return new WP_REST_Response( array( 'message' => 'Load more posts!' ), 200 );
// }

