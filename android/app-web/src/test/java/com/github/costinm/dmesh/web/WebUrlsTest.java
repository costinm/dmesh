package com.github.costinm.dmesh.web;

import org.junit.Assert;
import org.junit.Test;

public class WebUrlsTest {
    @Test
    public void adminUrlOpensSshMeshAdmin() {
        Assert.assertEquals("http://127.0.0.1:18480/_m/adm", WebUrls.adminUrl());
    }
}
