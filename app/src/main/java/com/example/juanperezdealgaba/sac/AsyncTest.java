package com.example.juanperezdealgaba.sac;

import android.content.Context;
import android.os.AsyncTask;
import android.util.Log;
import android.widget.TextView;

import java.io.FileWriter;

class MyTaskParamsTest {
    String randomString;
    FileWriter writer;
    TextView results;
    Context  context;

    MyTaskParamsTest(String randomString, FileWriter writer, TextView results, Context context) {
        this.randomString = randomString;
        this.writer = writer;
        this.results = results;
        this.context = context;
    }
}

public class AsyncTest extends AsyncTask<MyTaskParamsTest,Void,TextView> {

    @Override
    protected TextView doInBackground(MyTaskParamsTest... paramsTests) {
            String randomString = paramsTests[0].randomString;
            FileWriter writer = paramsTests[0].writer;
            TextView results = paramsTests[0].results;
            Context context = paramsTests[0].context;
            try {
                SuperTest test = new SuperTest();

                test.startTest(randomString, context, results, writer);

            } catch (Exception i) {
                Log.e("Test", i.getMessage(), i);
            }
            return results;
        }
}
