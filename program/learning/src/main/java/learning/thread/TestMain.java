package learning.thread;

import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * @author xuan
 * @date 2020/5/18 11:16
 */

public class TestMain {
    public static void main(String[] args) throws InterruptedException {
//        Test test=new Test();
//        test.run();
//        System.out.println("waiting!");
//        0:9
//        0:8
//        0:7
//        0:6
//        0:5
//        0:4
//        0:3
//        0:2
//        0:1
//        0:end
//        waiting!
//        Thread t=new Thread(new Test());
//        t.start();
//        System.out.println("waiting!");
//        waiting!
//        1:9
//        1:8
//        1:7
//        1:6
//        1:5
//        1:4
//        1:3
//        1:2
//        1:1
//        1:end
//        for (int i=0;i<5;i++){
//            new Thread(new Test()).start();
//            System.out.println("waiting!"+i);
//        }
//        ExecutorService exec= Executors.newFixedThreadPool(5);
//        for (int i=0;i<5;i++){
//            exec.execute(new Test());
//        }
//        exec.shutdown();
        for (int i=0;i<10;i++){
            Thread daemon=new Thread(new Test());
            daemon.setDaemon(true);
            daemon.start();
        }
        TimeUnit.MILLISECONDS.sleep(1);
    }
}
