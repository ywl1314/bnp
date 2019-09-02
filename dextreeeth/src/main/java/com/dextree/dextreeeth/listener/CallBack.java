package com.dextree.dextreeeth.listener;

public abstract  interface CallBack<T> {
    void end(T t);
    void start();
    void error();
}
