package com.xebyte.offline;

import com.xebyte.core.FrontEndProgramProvider;
import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.Response;
import com.xebyte.core.SwingThreadingStrategy;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import javax.swing.SwingUtilities;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/** Mocked windows only: no Ghidra session, HTTP listener or project files. */
public class FrontEndProgramSwitchTest {
    private final PluginTool tool = mock(PluginTool.class);
    private final Project project = mock(Project.class);
    private final ToolManager tools = mock(ToolManager.class);
    private final FrontEndProgramProvider provider;

    public FrontEndProgramSwitchTest() {
        when(tool.getProject()).thenReturn(project);
        when(project.getToolManager()).thenReturn(tools);
        when(tools.getRunningTools()).thenReturn(new PluginTool[0]);
        provider = new FrontEndProgramProvider(tool, this);
    }

    private Program program(String name) {
        Program p = mock(Program.class);
        DomainFile file = mock(DomainFile.class);
        when(file.getPathname()).thenReturn("/" + name);
        when(p.getDomainFile()).thenReturn(file);
        when(p.getName()).thenReturn(name);
        return p;
    }

    private ProgramManager browser(Program current, Program... open) {
        ProgramManager pm = mock(ProgramManager.class);
        AtomicReference<Program> focus = new AtomicReference<>(current);
        when(pm.getCurrentProgram()).thenAnswer(inv -> focus.get());
        when(pm.getAllOpenPrograms()).thenReturn(open);
        doAnswer(inv -> {
            assertTrue("ProgramManager changes must run on the EDT",
                SwingUtilities.isEventDispatchThread());
            focus.set(inv.getArgument(0));
            return null;
        }).when(pm).setCurrentProgram(any());
        doAnswer(inv -> {
            assertTrue("Opening a cached program must run on the EDT",
                SwingUtilities.isEventDispatchThread());
            return null;
        }).when(pm).openProgram(any(Program.class));
        return pm;
    }

    private void windows(ProgramManager... managers) {
        PluginTool[] windows = new PluginTool[managers.length];
        for (int i = 0; i < managers.length; i++) {
            windows[i] = mock(PluginTool.class);
            when(windows[i].getService(ProgramManager.class)).thenReturn(managers[i]);
        }
        when(tools.getRunningTools()).thenReturn(windows);
    }

    private Response switchTo(Program program) {
        return new ProgramScriptService(provider, new SwingThreadingStrategy())
            .switchProgram(program.getDomainFile().getPathname());
    }

    private void assertSwitched(Program target, Response response) {
        assertTrue("expected a successful switch: " + response, response instanceof Response.Ok);
        Map<?, ?> data = (Map<?, ?>) ((Response.Ok) response).data();
        assertEquals(true, data.get("success"));
        assertEquals(target.getDomainFile().getPathname(), data.get("path"));
        assertSame(target, provider.getCurrentProgram());
    }

    @Test
    public void switchesWithinOneBrowserOnUiThread() {
        Program a = program("a.sys");
        Program b = program("b.sys");
        ProgramManager pm = browser(a, a, b);
        windows(pm);

        assertSwitched(b, switchTo(b));
        verify(pm, never()).openProgram(any(Program.class));
    }

    @Test
    public void cachedTargetIsShownInExistingBrowser() {
        Program a = program("a.sys");
        Program b = program("afd-10.0.26100.9711-9541.sys");
        ProgramManager pm = browser(a, a);
        windows(pm);
        provider.trackOpenProgram(b);

        assertSwitched(b, switchTo(b));
        verify(pm).openProgram(b);
        verify(pm).setCurrentProgram(b);
    }

    @Test
    public void secondBrowserWinsOverFirstAndStillFollowsItsUiFocus() throws Exception {
        Program a = program("a.sys");
        Program b = program("b.sys");
        Program c = program("c.sys");
        ProgramManager first = browser(a, a);
        ProgramManager second = browser(c, b, c);
        windows(first, second);

        assertSwitched(b, switchTo(b));
        assertSame(second, provider.findProgramManager());
        verify(first, never()).setCurrentProgram(any());
        SwingUtilities.invokeAndWait(() -> second.setCurrentProgram(c));
        assertSame("GUI tab changes must still take effect", c, provider.getCurrentProgram());

        // Removing the selected window must not leave focus pinned to its stale manager.
        windows(first);
        assertSame(a, provider.getCurrentProgram());
        assertSame(first, provider.findProgramManager());
    }

    @Test
    public void cachedTargetWithoutAnyBrowserUsesProviderContext() {
        Program a = program("a.sys");
        Program b = program("b.sys");
        provider.trackOpenProgram(a);
        provider.trackOpenProgram(b);

        assertSwitched(b, switchTo(b));
        assertNull(provider.findProgramManager());
    }

    @Test
    public void failedUiSwitchReturnsErrorAndKeepsPreviousContext() {
        Program a = program("a.sys");
        Program b = program("b.sys");
        ProgramManager pm = browser(a, a);
        windows(pm);
        provider.trackOpenProgram(b);
        doThrow(new IllegalStateException("cannot open target")).when(pm).openProgram(b);

        Response response = switchTo(b);

        assertTrue(response.toString(), response instanceof Response.Err);
        assertTrue(((Response.Err) response).message().contains("Failed to switch program"));
        assertTrue(((Response.Err) response).message().contains("cannot open target"));
        assertSame(a, provider.getCurrentProgram());
        verify(pm, never()).setCurrentProgram(b);
    }
}
