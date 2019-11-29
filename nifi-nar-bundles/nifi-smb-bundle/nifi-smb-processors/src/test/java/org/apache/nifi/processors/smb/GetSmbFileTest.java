package org.apache.nifi.processors.smb;

import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import org.apache.nifi.util.TestRunner;
import org.apache.nifi.util.TestRunners;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockitoAnnotations;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class GetSmbFileTest {
    private TestRunner testRunner;

    private SMBClient smbClient;
    private Connection connection;
    private Session session;
    private DiskShare diskShare;
    private File smbfile;
    private ByteArrayOutputStream baOutputStream;

    private final static String HOSTNAME = "host";
    private final static String SHARE = "share";
    private final static String DIRECTORY = "nifi\\input";
    private final static String DOMAIN = "";
    private final static String USERNAME = "user";
    private final static String PASSWORD = "pass";

    private void setupSmbProcessor() throws IOException {
        testRunner.setProperty(GetSmbFile.HOSTNAME, HOSTNAME);
        testRunner.setProperty(GetSmbFile.SHARE, SHARE);
        testRunner.setProperty(GetSmbFile.DIRECTORY, DIRECTORY);
        if (!DOMAIN.isEmpty()) {
            testRunner.setProperty(GetSmbFile.DOMAIN, DOMAIN);
        }
        testRunner.setProperty(GetSmbFile.USERNAME, USERNAME);
        testRunner.setProperty(GetSmbFile.PASSWORD, PASSWORD);

        // used when checking files being locked
//        testRunner.setProperty(GetSmbFile.SHARE_ACCESS, GetSmbFile.SHARE_ACCESS_READWRITEDELETE);
//        testRunner.setProperty(GetSmbFile.KEEP_SOURCE_FILE, "true");


        GetSmbFile GetSmbFile = (GetSmbFile) testRunner.getProcessor();
//        GetSmbFile.initSmbClient(smbClient);
    }

    @Before
    public void init() throws IOException {
        testRunner = TestRunners.newTestRunner(GetSmbFile.class);
        MockitoAnnotations.initMocks(this);
        setupSmbProcessor();
    }

    @Test
    public void testIntegration() throws IOException {
        testRunner.run();
    }
}
