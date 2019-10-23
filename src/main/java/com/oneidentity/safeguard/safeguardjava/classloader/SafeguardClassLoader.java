package com.oneidentity.safeguard.safeguardjava.classloader;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class SafeguardClassLoader extends URLClassLoader {

    private static SafeguardClassLoader instance = null;
    private static Object mutex = new Object();
    
    private final ClassLoader sysClzLoader;

    public static SafeguardClassLoader getInstance(URL[] urls) {
        SafeguardClassLoader loader = instance;
        if (loader == null) {
            synchronized(mutex) {
                loader = instance;
                if (loader == null)
                    instance = loader = new SafeguardClassLoader(urls);
            }
        }
        return loader;
    }
    
    private SafeguardClassLoader(URL[] urls) {
        super(urls, null);
        sysClzLoader = getSystemClassLoader();
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        // has the class loaded already?
        Class<?> loadedClass = findLoadedClass(name);
        if (loadedClass == null) {
            try {
                // find the class from given jar urls as in first constructor parameter.
                if (loadedClass == null) {
                    loadedClass = findClass(name);
                }
            } catch (ClassNotFoundException e) {
                // class is not found in the given urls.
                // Let's try it in parent classloader.
                // If class is still not found, then this method will throw class not found ex.
                loadedClass = super.loadClass(name, resolve);
            }
        }
            
        if (loadedClass == null) {
            try {
                if (sysClzLoader != null) {
                    loadedClass = sysClzLoader.loadClass(name);
                }
            } catch (ClassNotFoundException ex) {
                // class not found in system class loader... silently skipping
            }
        }

        if (resolve) {      // marked to resolve
            resolveClass(loadedClass);
        }
        return loadedClass;
    }



    @Override
    public Enumeration<URL> getResources(String name) throws IOException {
        List<URL> allRes = new LinkedList<>();

        // load resource from this classloader
        Enumeration<URL> thisRes = findResources(name);
        if (thisRes != null) {
            while (thisRes.hasMoreElements()) {
                allRes.add(thisRes.nextElement());
            }
        }

        // then try finding resources from parent classloaders
        Enumeration<URL> parentRes = super.findResources(name);
        if (parentRes != null) {
            while (parentRes.hasMoreElements()) {
                allRes.add(parentRes.nextElement());
            }
        }

        // load resources from sys class loader
        Enumeration<URL> sysResources = sysClzLoader.getResources(name);
        if (sysResources != null) {
            while (sysResources.hasMoreElements()) {
                allRes.add(sysResources.nextElement());
            }
        }

        return new Enumeration<URL>() {
            Iterator<URL> it = allRes.iterator();

            @Override
            public boolean hasMoreElements() {
                return it.hasNext();
            }

            @Override
            public URL nextElement() {
                return it.next();
            }
        };
    }

    @Override
    public URL getResource(String name) {
        URL res = null;
        if (res == null) {
            res = findResource(name);
        }
        if (res == null) {
            res = super.getResource(name);
        }
        if (sysClzLoader != null) {
            res = sysClzLoader.getResource(name);
        }
        return res;
    }
}
