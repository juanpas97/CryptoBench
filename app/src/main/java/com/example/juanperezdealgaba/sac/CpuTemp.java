package com.example.juanperezdealgaba.sac;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.util.Calendar;
import java.util.Date;

public class CpuTemp {

    public float getCpuTemp(int id, FileWriter writer_temp) {
        Process p;
        try {
            p = Runtime.getRuntime().exec("cat sys/class/thermal/thermal_zone0/temp");
            p.waitFor();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            Global global = new Global();
            String line = reader.readLine();
            float temp = Float.parseFloat(line);
            Date currentTime = Calendar.getInstance().getTime();
            writer_temp.write("Time: " + currentTime + "");
            if (id == 1) {
                temp = Float.parseFloat(line) / 1000.0f;
                writer_temp.write("The temperature is:" + temp + "\n");
                return temp;
            }

            writer_temp.write("The temperature is:" + temp + "\n");
            return  temp;

        } catch (Exception e) {
            System.out.println("Exception");
            e.printStackTrace();
            return 0.0f;
        }
    }

}
