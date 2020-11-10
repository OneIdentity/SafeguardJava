package com.oneidentity.safeguard.safeguardjava.data;

/**
 *  A list of private key formats supported by Safeguard.
 */
public enum KeyFormat
{
    /**
     *  OpenSSH legacy PEM format
     */
    OpenSsh,
    /**
     *  Tectia format for use with tools from SSH.com
    */
    Ssh2,
    /**
     *  PuttY format for use with PuTTY tools
    */
    Putty
}