package com.xebyte.offline;

import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.Response;
import junit.framework.TestCase;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * {@code /list_scripts} (v7.0.0) must return real filesystem entries, not the old
 * "open the Script Manager" stub text.
 *
 * <p>The handler searches only {@code ~/ghidra_scripts}, without recursion.
 * Each test points {@code user.home} at a temporary directory. The working
 * directory and Ghidra installation must not contribute additional scripts.
 * Pure filesystem — no Ghidra, no Swing.
 */
public class ListGhidraScriptsOfflineTest extends TestCase {

    private String originalHome;
    private File fakeHome;
    private File scriptsDir;
    private ProgramScriptService svc;

    @Override
    protected void setUp() throws Exception {
        originalHome = System.getProperty("user.home");
        fakeHome = Files.createTempDirectory("mcp-list-home").toFile();
        scriptsDir = new File(fakeHome, "ghidra_scripts");
        assertTrue(scriptsDir.mkdirs());
        System.setProperty("user.home", fakeHome.getAbsolutePath());
        svc = new ProgramScriptService(ServiceFactory.stubProvider(), new NoopThreadingStrategy());
    }

    @Override
    protected void tearDown() {
        if (originalHome != null) {
            System.setProperty("user.home", originalHome);
        }
        deleteTree(fakeHome);
    }

    private static void deleteTree(File f) {
        if (f == null || !f.exists()) return;
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteTree(k);
        f.delete();
    }

    private File writeScript(String name, String body) throws Exception {
        File f = new File(scriptsDir, name);
        Files.writeString(f.toPath(), body);
        return f;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> okData(Response r) {
        assertTrue("expected Ok, got " + r, r instanceof Response.Ok);
        Object data = ((Response.Ok) r).data();
        assertTrue("expected a Map payload, got " + data, data instanceof Map);
        return (Map<String, Object>) data;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> scriptsOf(Map<String, Object> data) {
        Object s = data.get("scripts");
        assertTrue("payload must carry a scripts list, got " + data.keySet(), s instanceof List);
        return (List<Map<String, Object>>) s;
    }

    /** Only the entries that live under this test's temp scripts dir. */
    private List<Map<String, Object>> mine(Map<String, Object> data) {
        String prefix = scriptsDir.getAbsolutePath();
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> e : scriptsOf(data)) {
            Object p = e.get("path");
            if (p instanceof String && ((String) p).startsWith(prefix)) out.add(e);
        }
        return out;
    }

    public void testReturnsFilesystemEntriesNotGuiInstructions() throws Exception {
        writeScript("Alpha.java", "public class Alpha {}");
        writeScript("Beta.py", "print('hi')");

        Map<String, Object> data = okData(svc.listGhidraScripts(""));

        // The stub returned GUI instructions; the real handler must not.
        assertFalse("must not be the GUI stub", data.containsKey("instructions"));
        assertTrue("must report searched_dirs", data.containsKey("searched_dirs"));
        assertTrue("must report a count", data.containsKey("count"));
        assertTrue("must report scripts", data.containsKey("scripts"));

        // Discovery is restricted to the user scripts directory.
        List<Map<String, Object>> mine = mine(data);
        assertEquals(1, mine.size());
        assertEquals(1, ((Number) data.get("count")).intValue());
        assertEquals(List.of(scriptsDir.getAbsolutePath()), data.get("searched_dirs"));
    }

    public void testEachEntryCarriesNamePathSizeModified() throws Exception {
        File written = writeScript("Gamma.java", "public class Gamma {}");

        List<Map<String, Object>> mine = mine(okData(svc.listGhidraScripts("")));

        assertEquals(1, mine.size());
        Map<String, Object> entry = mine.get(0);
        assertEquals("Gamma.java", entry.get("name"));
        assertEquals(written.getAbsolutePath(), entry.get("path"));
        assertTrue("size must be a number", entry.get("size") instanceof Number);
        assertTrue("modified must be present", entry.get("modified") != null);
    }

    public void testFilterNarrowsBySubstringCaseInsensitive() throws Exception {
        writeScript("ZqFind830.java", "public class ZqFind830 {}");
        writeScript("zqfind_helpers.py", "pass");
        writeScript("ZqUnrelated.java", "public class ZqUnrelated {}");

        // Unique prefix ZqFind/ZqUnrelated avoids colliding with real scripts elsewhere.
        List<Map<String, Object>> mine = mine(okData(svc.listGhidraScripts("ZQFIND")));

        assertEquals(1, mine.size());
        for (Map<String, Object> e : mine) {
            assertTrue(((String) e.get("name")).toLowerCase().contains("zqfind"));
        }
    }

    public void testFilterEchoesBackInPayload() throws Exception {
        Map<String, Object> data = okData(svc.listGhidraScripts("alpha"));
        assertEquals("alpha", data.get("filter"));
    }

    public void testEmptyFilterReportsNoneNotEmptyString() throws Exception {
        Map<String, Object> data = okData(svc.listGhidraScripts(""));
        assertEquals("none", data.get("filter"));
    }

    public void testNonScriptFilesAreExcluded() throws Exception {
        writeScript("Real.java", "public class Real {}");
        writeScript("notes.txt", "not a script");
        writeScript("README.md", "nope");
        writeScript("Disabled.py", "raise Exception('must not run')");

        List<Map<String, Object>> mine = mine(okData(svc.listGhidraScripts("")));

        assertEquals(1, mine.size());
        assertEquals("Real.java", mine.get(0).get("name"));
    }

    public void testMissingScriptsDirectoryIsSafe() {
        deleteTree(scriptsDir);
        assertFalse(scriptsDir.exists());

        Map<String, Object> data = okData(svc.listGhidraScripts(""));

        // A missing home scripts directory must not fall back to other locations.
        assertTrue(mine(data).isEmpty());
        assertEquals(0, ((Number) data.get("count")).intValue());
        // searched_dirs still lists the attempted location for diagnosability.
        assertTrue(data.get("searched_dirs") instanceof List);
    }
}
