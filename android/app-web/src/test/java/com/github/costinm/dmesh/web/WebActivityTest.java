package com.github.costinm.dmesh.web;

import org.junit.Assert;
import org.junit.Test;

public class WebActivityTest {
    @Test
    public void adminUrlOpensSshMeshAdmin() {
        Assert.assertEquals("http://127.0.0.1:18480/_m/adm", WebActivity.DEFAULT_ADMIN_URL);
    }
}
