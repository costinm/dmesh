package com.github.costinm.dmesh.chat;

import android.content.Context;
import android.util.AttributeSet;
import android.util.Log;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputMethodManager;
import android.view.inputmethod.BaseInputConnection;

public class EguiSurfaceView extends SurfaceView implements SurfaceHolder.Callback {
    private static final String TAG = "EguiSurfaceView";

    static {
        System.loadLibrary("dmeshui");
    }

    private long nativeHandle;

    public EguiSurfaceView(Context context) {
        super(context);
        init();
    }

    public EguiSurfaceView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public EguiSurfaceView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private void init() {
        getHolder().addCallback(this);
        setFocusable(true);
        setFocusableInTouchMode(true);
        requestFocus();

        float density = getResources().getDisplayMetrics().density;
        nativeHandle = nativeInit(getContext().getApplicationContext(), density);
        Log.i(TAG, "Initialized nativeHandle=" + nativeHandle + " density=" + density);
    }

    public void setBottomInset(float insetsBottom) {
        if (nativeHandle != 0) {
            nativeSetInsets(nativeHandle, insetsBottom);
        }
    }

    @Override
    public void surfaceCreated(SurfaceHolder holder) {
        Log.i(TAG, "surfaceCreated");
    }

    @Override
    public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
        Log.i(TAG, "surfaceChanged: " + width + "x" + height);
        if (nativeHandle != 0) {
            nativeSurfaceCreated(nativeHandle, holder.getSurface(), width, height);
            nativeSurfaceChanged(nativeHandle, width, height);
        }
    }

    @Override
    public void surfaceDestroyed(SurfaceHolder holder) {
        Log.i(TAG, "surfaceDestroyed");
        if (nativeHandle != 0) {
            nativeSurfaceDestroyed(nativeHandle);
        }
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        // Request focus and open soft keyboard when touched
        requestFocus();
        InputMethodManager imm = (InputMethodManager) getContext().getSystemService(Context.INPUT_METHOD_SERVICE);
        if (imm != null) {
            imm.showSoftInput(this, InputMethodManager.SHOW_IMPLICIT);
        }

        if (nativeHandle != 0) {
            nativeTouchEvent(nativeHandle, event.getActionMasked(), event.getX(), event.getY());
        }
        return true;
    }

    @Override
    public boolean onGenericMotionEvent(MotionEvent event) {
        if ((event.getSource() & android.view.InputDevice.SOURCE_CLASS_POINTER) != 0) {
            if (event.getAction() == MotionEvent.ACTION_SCROLL) {
                float vScroll = event.getAxisValue(MotionEvent.AXIS_VSCROLL);
                float hScroll = event.getAxisValue(MotionEvent.AXIS_HSCROLL);
                if (nativeHandle != 0) {
                    float density = getResources().getDisplayMetrics().density;
                    // egui scroll delta: positive vScroll scrolls up (reveals content above)
                    nativeScroll(nativeHandle, hScroll * 40f, vScroll * 40f);
                    return true;
                }
            }
        }
        return super.onGenericMotionEvent(event);
    }

    @Override
    public boolean onCheckIsTextEditor() {
        return true;
    }

    @Override
    public InputConnection onCreateInputConnection(EditorInfo outAttrs) {
        outAttrs.inputType = EditorInfo.TYPE_CLASS_TEXT | EditorInfo.TYPE_TEXT_FLAG_AUTO_CORRECT;
        outAttrs.imeOptions = EditorInfo.IME_ACTION_DONE | EditorInfo.IME_FLAG_NO_EXTRACT_UI;
        return new BaseInputConnection(this, false) {
            @Override
            public boolean commitText(CharSequence text, int newCursorPosition) {
                Log.d(TAG, "InputConnection commitText: " + text);
                if (text != null && text.length() > 0 && nativeHandle != 0) {
                    nativeCommitText(nativeHandle, text.toString());
                }
                return true;
            }

            @Override
            public boolean deleteSurroundingText(int beforeLength, int afterLength) {
                if (beforeLength > 0 && nativeHandle != 0) {
                    // Send Backspace (Keycode 67 = AKEYCODE_DEL)
                    nativeKey(nativeHandle, 67, true);
                    nativeKey(nativeHandle, 67, false);
                }
                return super.deleteSurroundingText(beforeLength, afterLength);
            }

            @Override
            public boolean sendKeyEvent(KeyEvent event) {
                Log.d(TAG, "InputConnection sendKeyEvent: " + event);
                boolean down = event.getAction() == KeyEvent.ACTION_DOWN;
                if (event.getKeyCode() == KeyEvent.KEYCODE_ENTER) {
                    if (nativeHandle != 0) {
                        nativeKey(nativeHandle, 66, down);
                    }
                    return true;
                } else if (event.getKeyCode() == KeyEvent.KEYCODE_DEL) {
                    if (nativeHandle != 0) {
                        nativeKey(nativeHandle, 67, down);
                    }
                    return true;
                }
                return super.sendKeyEvent(event);
            }

            @Override
            public boolean performEditorAction(int actionCode) {
                Log.d(TAG, "InputConnection performEditorAction: " + actionCode);
                if (nativeHandle != 0) {
                    nativeKey(nativeHandle, 66, true);
                    nativeKey(nativeHandle, 66, false);
                }
                return true;
            }
        };
    }

    @Override
    public boolean dispatchKeyEvent(KeyEvent event) {
        Log.d(TAG, "dispatchKeyEvent: keyCode=" + event.getKeyCode() + " action=" + event.getAction());
        boolean down = event.getAction() == KeyEvent.ACTION_DOWN;
        if (event.getKeyCode() == KeyEvent.KEYCODE_ENTER) {
            if (nativeHandle != 0) {
                nativeKey(nativeHandle, 66, down);
            }
            return true;
        } else if (event.getKeyCode() == KeyEvent.KEYCODE_DEL) {
            if (nativeHandle != 0) {
                nativeKey(nativeHandle, 67, down);
            }
            return true;
        } else if (event.getKeyCode() == KeyEvent.KEYCODE_DPAD_UP) {
            if (nativeHandle != 0) {
                nativeKey(nativeHandle, 19, down);
            }
            return true;
        } else if (event.getKeyCode() == KeyEvent.KEYCODE_DPAD_DOWN) {
            if (nativeHandle != 0) {
                nativeKey(nativeHandle, 20, down);
            }
            return true;
        } else if (event.getKeyCode() == KeyEvent.KEYCODE_TAB) {
            if (nativeHandle != 0) {
                nativeKey(nativeHandle, 61, down);
            }
            return true;
        }
        if (down) {
            int unicode = event.getUnicodeChar();
            if (unicode > 0 && nativeHandle != 0) {
                nativeCommitText(nativeHandle, String.valueOf((char) unicode));
                return true;
            }
        }
        return super.dispatchKeyEvent(event);
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        Log.d(TAG, "onKeyDown: keyCode=" + keyCode + " action=" + event.getAction());
        if (nativeHandle != 0) {
            if (keyCode == KeyEvent.KEYCODE_ENTER) {
                nativeKey(nativeHandle, 66, true);
                return true;
            } else if (keyCode == KeyEvent.KEYCODE_DEL) {
                nativeKey(nativeHandle, 67, true);
                return true;
            } else if (keyCode == KeyEvent.KEYCODE_DPAD_UP) {
                nativeKey(nativeHandle, 19, true);
                return true;
            } else if (keyCode == KeyEvent.KEYCODE_DPAD_DOWN) {
                nativeKey(nativeHandle, 20, true);
                return true;
            } else if (keyCode == KeyEvent.KEYCODE_TAB) {
                nativeKey(nativeHandle, 61, true);
                return true;
            }
            int unicode = event.getUnicodeChar();
            if (unicode > 0) {
                nativeCommitText(nativeHandle, String.valueOf((char) unicode));
                return true;
            }
        }
        return super.onKeyDown(keyCode, event);
    }

    @Override
    public boolean onKeyUp(int keyCode, KeyEvent event) {
        if (nativeHandle != 0) {
            if (keyCode == KeyEvent.KEYCODE_ENTER) {
                nativeKey(nativeHandle, 66, false);
                return true;
            } else if (keyCode == KeyEvent.KEYCODE_DEL) {
                nativeKey(nativeHandle, 67, false);
                return true;
            } else if (keyCode == KeyEvent.KEYCODE_DPAD_UP) {
                nativeKey(nativeHandle, 19, false);
                return true;
            } else if (keyCode == KeyEvent.KEYCODE_DPAD_DOWN) {
                nativeKey(nativeHandle, 20, false);
                return true;
            } else if (keyCode == KeyEvent.KEYCODE_TAB) {
                nativeKey(nativeHandle, 61, false);
                return true;
            }
        }
        return super.onKeyUp(keyCode, event);
    }

    public void destroy() {
        if (nativeHandle != 0) {
            nativeDestroy(nativeHandle);
            nativeHandle = 0;
        }
    }

    // Native method declarations
    private static native long nativeInit(Context context, float density);
    private static native void nativeSurfaceCreated(long ptr, Surface surface, int width, int height);
    private static native void nativeSurfaceChanged(long ptr, int width, int height);
    private static native void nativeSurfaceDestroyed(long ptr);
    private static native void nativeTouchEvent(long ptr, int action, float x, float y);
    private static native void nativeCommitText(long ptr, String text);
    private static native void nativeKey(long ptr, int keycode, boolean down);
    private static native void nativeScroll(long ptr, float dx, float dy);
    private static native void nativeSetInsets(long ptr, float insetsBottom);
    private static native void nativeDestroy(long ptr);
}
