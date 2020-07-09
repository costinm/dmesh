package com.github.costinm.dmesh.android.msg;

import android.os.Message;

/**
 * Interface for processing incoming messages. Register with 'subscribe(prefix, handler).
 * Any message, local or received from remote, will result in a call.
 * <p>
 * Used to be Handler.Callback - but it's harder to search for usages and gets confusing.
 */
public interface MessageHandler {

    /**
     * @param topic
     * @param msgType
     * @param m       the actual message. The Bundle has the parsed metadata.
     * @param replyTo null if the message was generated locally.
     */
    void handleMessage(String topic, String msgType, Message m, MsgConn replyTo, String[] args);
}
