package learning.thread;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author xuan
 * @date 2020/5/21 15:14
 */

public class ExceptionThread implements Runnable {
    /**
     * When an object implementing interface <code>Runnable</code> is used
     * to create a thread, starting the thread causes the object's
     * <code>run</code> method to be called in that separately executing
     * thread.
     * <p>
     * The general contract of the method <code>run</code> is that it may
     * take any action whatsoever.
     *
     * @see Thread#run()
     */
    @Override
    public void run() {
        throw new RuntimeException();
    }
    static class MyUncaughtExceptionHandler implements Thread.UncaughtExceptionHandler{

        /**
         * Method invoked when the given thread terminates due to the
         * given uncaught exception.
         * <p>Any exception thrown by this method will be ignored by the
         * Java Virtual Machine.
         *
         * @param t the thread
         * @param e the exception
         */
        @Override
        public void uncaughtException(Thread t, Throwable e) {
            System.out.println(t+":caught-"+e);
        }
    }
    public static void main(String[] args) {
//        try {
//            ExecutorService exec= Executors.newCachedThreadPool();
//            exec.execute(new ExceptionThread());
//            exec.shutdown();
//        } catch (Exception e) {
//            System.out.println("Exception");
//        }
//        Thread t=new Thread(new ExceptionThread());
//        t.setUncaughtExceptionHandler(new MyUncaughtExceptionHandler());
//        t.start();
    }
}
