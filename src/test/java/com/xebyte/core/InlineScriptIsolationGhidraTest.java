package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.plugin.core.osgi.GhidraSourceBundle;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/** Exercise the actual compiler/OSGi lifecycle, including recovery after a failed build. */
public class InlineScriptIsolationGhidraTest {
    @BeforeClass
    public static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR required", installDir != null && !installDir.isBlank());
        assumeTrue("GHIDRA_MCP_ALLOW_SCRIPTS=1 required",
            SecurityConfig.getInstance().areScriptsAllowed());
        if (!Application.isInitialized()) {
            ApplicationConfiguration config = new ApplicationConfiguration();
            config.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)), config);
        }
    }

    @Test
    public void inlineRunsOnceAndDiscardsSuccessAndFailureWithoutBuildingOtherScripts() throws Exception {
        ProgramBuilder builder = new ProgramBuilder("inline-target", ProgramBuilder._X64, "gcc", this);
        Path unrelated = Files.createTempDirectory("unrelated-scripts-");
        ResourceFile unrelatedRoot = new ResourceFile(unrelated.toFile());
        GhidraScriptUtil.acquireBundleHostReference();
        BundleHost host = GhidraScriptUtil.getBundleHost();
        // Minimal test application does not run the GUI/headless provider discovery.
        var javaProvider = new ghidra.app.script.JavaScriptProvider();
        GhidraScriptUtil.getProviders().add(0, javaProvider);
        try {
            // Deliberately broken persistent source must neither block nor appear in inline output.
            Path broken = unrelated.resolve("InlineProbe.java");
            Files.writeString(broken, "this is not valid Java");
            host.enable(unrelatedRoot);
            int bundleCount = host.getGhidraBundles().size();
            ProgramProvider provider = mock(ProgramProvider.class);
            when(provider.resolveProgram(any())).thenReturn(builder.getProgram());
            when(provider.getProgram(any())).thenReturn(builder.getProgram());
            when(provider.getCurrentProgram()).thenReturn(builder.getProgram());
            when(provider.getAllOpenPrograms()).thenReturn(
                new ghidra.program.model.listing.Program[] {builder.getProgram()});
            ProgramScriptService service = new ProgramScriptService(provider, new DirectThreadingStrategy());
            System.clearProperty("ghidra.mcp.inline.constructions");
            String code = "import ghidra.app.script.GhidraScript;\n"
                + "public class InlineProbe extends GhidraScript {\n"
                + " public InlineProbe() { System.setProperty(\"ghidra.mcp.inline.constructions\", "
                + "System.getProperty(\"ghidra.mcp.inline.constructions\", \"\") + \"x\"); }\n"
                + " public void run() { println(currentProgram.getName() + \":\" + getScriptArgs()[0]); }\n}";
            Map<?, ?> success = data(service.runScriptInline(code, "argument", "inline-target"));
            assertEquals(success.toString(), true, success.get("success"));
            assertTrue(success.toString(), success.get("console_output").toString().contains("inline-target:argument"));
            assertEquals("the loaded instance must be executed without constructing another", "x",
                System.getProperty("ghidra.mcp.inline.constructions"));
            assertDiscarded(success, host, bundleCount);

            Map<?, ?> compileFailure = data(service.runScriptInline(
                code.replace("println(currentProgram", "invalidSyntax(currentProgram"), "argument", "inline-target"));
            assertEquals(compileFailure.toString(), false, compileFailure.get("success"));
            assertDiscarded(compileFailure, host, bundleCount);

            Map<?, ?> runtimeFailure = data(service.runScriptInline(
                "throw new IllegalStateException(\"inline-boom\");", "", "inline-target"));
            assertEquals(runtimeFailure.toString(), false, runtimeFailure.get("success"));
            assertTrue(runtimeFailure.toString(), runtimeFailure.toString().contains("inline-boom"));
            assertDiscarded(runtimeFailure, host, bundleCount);

            Map<?, ?> retry = data(service.runScriptInline(code, "retry", "inline-target"));
            assertEquals(retry.toString(), true, retry.get("success"));
            assertDiscarded(retry, host, bundleCount);
            assertEquals("this is not valid Java", Files.readString(broken));
            assertTrue(((GhidraSourceBundle) host.getGhidraBundle(unrelatedRoot)).getAllErrors().isEmpty());
        } finally {
            host.remove(unrelatedRoot);
            GhidraScriptUtil.getProviders().remove(javaProvider);
            GhidraScriptUtil.releaseBundleHostReference();
            Files.deleteIfExists(unrelated.resolve("InlineProbe.java"));
            Files.deleteIfExists(unrelated);
            System.clearProperty("ghidra.mcp.inline.constructions");
            builder.dispose();
        }
    }

    @Test
    public void persistentExecutionStillCopiesExternalSourceAndKeepsTheOriginal() throws Exception {
        ProgramBuilder builder = new ProgramBuilder("persistent-target", ProgramBuilder._X64, "gcc", this);
        Path home = Files.createTempDirectory("persistent-script-home-");
        Path source = home.resolve("PersistentProbe.java");
        Path scripts = home.resolve("ghidra_scripts");
        String originalHome = System.getProperty("user.home");
        GhidraScriptUtil.acquireBundleHostReference();
        BundleHost host = GhidraScriptUtil.getBundleHost();
        var javaProvider = new ghidra.app.script.JavaScriptProvider();
        GhidraScriptUtil.getProviders().add(0, javaProvider);
        try {
            System.setProperty("user.home", home.toString());
            String code = "import ghidra.app.script.GhidraScript;\n"
                + "public class PersistentProbe extends GhidraScript { "
                + "public void run() { println(currentProgram.getName() + \":\" + getScriptArgs()[0]); }}";
            Files.writeString(source, code);
            ProgramProvider provider = mock(ProgramProvider.class);
            when(provider.getProgram(any())).thenReturn(builder.getProgram());
            ProgramScriptService service = new ProgramScriptService(provider, new DirectThreadingStrategy());
            Map<?, ?> result = data(service.runGhidraScript(
                source.toString(), "persistent-arg", "persistent-target", 5));
            assertEquals(result.toString(), true, result.get("success"));
            String output = result.get("console_output").toString();
            assertTrue(output, output.contains("Copied to: " + scripts.resolve("PersistentProbe.java")));
            assertTrue(output, output.contains("persistent-target:persistent-arg"));
            assertEquals(code, Files.readString(source));
            assertFalse("temporary copy must still be cleaned up",
                Files.exists(scripts.resolve("PersistentProbe.java")));
            assertNotNull("persistent source bundle remains registered",
                host.getGhidraBundle(new ResourceFile(scripts.toFile())));
            Files.writeString(scripts.resolve("PythonOnly.py"), "raise Exception('must not run')");
            Response unresolved = service.runGhidraScriptWithCapture(
                "PythonOnly", "", 5, true, "persistent-target");
            assertTrue(unresolved.toJson(), unresolved instanceof Response.Err);
            assertTrue(unresolved.toJson(), unresolved.toJson().contains("not found"));
        } finally {
            System.setProperty("user.home", originalHome);
            var bundle = host.getGhidraBundle(new ResourceFile(scripts.toFile()));
            if (bundle != null) {
                ((GhidraSourceBundle) bundle).clean();
                host.remove(bundle);
            }
            GhidraScriptUtil.getProviders().remove(javaProvider);
            GhidraScriptUtil.releaseBundleHostReference();
            Files.deleteIfExists(scripts.resolve("PersistentProbe.java"));
            Files.deleteIfExists(scripts.resolve("PythonOnly.py"));
            Files.deleteIfExists(scripts);
            Files.deleteIfExists(source);
            Files.deleteIfExists(home);
            builder.dispose();
        }
    }

    @Test
    public void jythonIsRejectedBeforeProgramLookupOrExecution() {
        ProgramProvider provider = mock(ProgramProvider.class);
        ProgramScriptService service = new ProgramScriptService(provider, new DirectThreadingStrategy());
        for (String path : new String[] {"Disabled.py", "/missing/Disabled.PY"}) {
            Response direct = service.runGhidraScript(path, "", "", 5);
            Response captured = service.runGhidraScriptWithCapture(path, "", 5, true, "");
            assertTrue(direct.toJson(), direct instanceof Response.Err);
            assertTrue(captured.toJson(), captured instanceof Response.Err);
            assertTrue(direct.toJson().contains("Python/Jython script support is disabled"));
            assertTrue(captured.toJson().contains("Python/Jython script support is disabled"));
        }
        verifyNoInteractions(provider);
    }

    private static Map<?, ?> data(Response response) {
        assertTrue(response.toJson(), response instanceof Response.Ok);
        return (Map<?, ?>) ((Response.Ok) response).data();
    }

    private static void assertDiscarded(Map<?, ?> response, BundleHost host, int bundleCount) {
        String output = response.get("console_output").toString();
        String scriptPath = output.lines().filter(line -> line.startsWith("Script: "))
            .findFirst().orElseThrow().substring("Script: ".length());
        Path sourceDir = Path.of(scriptPath).getParent();
        assertFalse("temporary source directory survives", Files.exists(sourceDir));
        assertNull(host.getGhidraBundle(new ResourceFile(sourceDir.toFile())));
        assertEquals(bundleCount, host.getGhidraBundles().size());
        Path compiled = GhidraSourceBundle.getCompiledBundlesDir().resolve(
            GhidraSourceBundle.sourceDirHash(new ResourceFile(sourceDir.toFile())));
        assertFalse("compiled bundle cache survives", Files.exists(compiled));
    }
}
