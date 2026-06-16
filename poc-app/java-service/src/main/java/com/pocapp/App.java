package com.pocapp;

import com.google.common.base.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Minimal entrypoint that genuinely references guava and slf4j so the
 * dependencies appear in the generated SBOM.
 */
public final class App {

    private static final Logger LOG = LoggerFactory.getLogger(App.class);

    private App() {
    }

    public static void main(String[] args) {
        String name = args.length > 0 ? args[0] : "world";
        LOG.info("poc-app java-service says hello to {}", Strings.nullToEmpty(name));
    }
}
