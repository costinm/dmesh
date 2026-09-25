package com.github.costinm.dmesh;

/** Handles one bounded mesh message record and returns its correlated reply. */
@FunctionalInterface
public interface MeshStreamHandler {
    MeshStream handle(MeshStream request) throws Exception;
}
