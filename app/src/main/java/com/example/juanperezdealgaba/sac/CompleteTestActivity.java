package com.example.juanperezdealgaba.sac;

import android.app.Activity;
import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.snatik.storage.Storage;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class CompleteTestActivity extends AppCompatActivity{

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        try {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_complete_test);
            Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
            setSupportActionBar(toolbar);

            final TextView complete_test_results = findViewById(R.id.complete_test_results);

            complete_test_results.setMovementMethod(new ScrollingMovementMethod());

            final EditText repetitions_test = findViewById(R.id.repetitions);

            final Button start_test = findViewById(R.id.start_complete_test);

            Storage storage = new Storage(getApplicationContext());

            String path = storage.getExternalStorageDirectory();

            final String newDir = path + File.separator + "CryptoBench";

            final File report = new File(newDir, "Report.txt");
            report.mkdirs();

            if (report.exists())
                report.delete();

            final FileWriter writer = new FileWriter(report);


            start_test.setOnClickListener(new View.OnClickListener() {

                @Override
                public void onClick(View view) {
                    int repetitions;

                    String check = repetitions_test.getText().toString();
                    if (check.matches("")) {
                        repetitions = 1;
                    } else {
                        repetitions = Integer.parseInt(repetitions_test.getText().toString());
                    }
                    System.out.println("Reptitions:" + repetitions);

                    CompleteTestParams paramsTest = new CompleteTestParams(writer, complete_test_results,repetitions);

                    CompleteTestAsync test = new CompleteTestAsync();
                    test.execute(paramsTest);

                }
            });

            FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
            fab.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                            .setAction("Action", null).show();
                }
            });
        }catch (IOException i){
            throw new RuntimeException(i);
        }
    }

}
