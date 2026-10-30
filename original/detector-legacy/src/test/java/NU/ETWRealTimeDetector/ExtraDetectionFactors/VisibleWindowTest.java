package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class VisibleWindowTest {
    private int screenRightBoundary = 1920;
    private int screenBottomBoundary = 1080;

    private List<Window> windowList = new ArrayList<>(Arrays.asList(
            new Window(-110, -10, -110, -10, true),

            new Window(-110, -10, 10, 110, false),
            new Window(-10, 90, 10, 110, true),
            new Window(10, 110, 10, 110, true),
            new Window(910, 1010, 10, 110, true),
            new Window(1110, 1210, 10, 110, false),


            new Window(10, 110, -110, -10, false),
            new Window(10, 110, -10, 90, true),
            new Window(10, 110, 10, 110, true),
            new Window(10, 110, 910, 1010, true),
            new Window(30000, 30001, 30000, 30001, false),
            new Window(10, 110, 1110, 1210, false)

    ));

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void visible() {
        VisibleWindow visibleWindow = VisibleWindow.getInstance("test");
        visibleWindow.setScreenBoundary(screenRightBoundary, screenBottomBoundary);
        windowList.stream().forEach(w -> {
            assertTrue(visibleWindow.visible(w.left, w.top, w.right, w.bottom) == w.visible);
        });
    }

    class Window {
        Window(int left, int right, int top, int bottom, boolean visible) {
            this.left = left;
            this.right = right;
            this.top = top;
            this.bottom = bottom;
            this.visible = visible;
        }

        int left;
        int right;
        int top;
        int bottom;
        boolean visible;
    }
}