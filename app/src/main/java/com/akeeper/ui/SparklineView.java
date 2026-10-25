package com.akeeper.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.util.AttributeSet;
import android.view.View;

import androidx.annotation.Nullable;

import com.akeeper.R;

/** Mini-courbe légère sans dépendance externe. */
public final class SparklineView extends View {
    private final Paint line = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint fill = new Paint(Paint.ANTI_ALIAS_FLAG);
    private long[] values = new long[0];

    public SparklineView(Context context, @Nullable AttributeSet attrs) {
        super(context, attrs);
        line.setStyle(Paint.Style.STROKE);
        line.setStrokeWidth(getResources().getDisplayMetrics().density * 2f);
        line.setStrokeCap(Paint.Cap.ROUND);
        line.setStrokeJoin(Paint.Join.ROUND);
        line.setColor(context.getColor(R.color.akeeper_turquoise));
        fill.setStyle(Paint.Style.FILL);
        fill.setColor((context.getColor(R.color.akeeper_turquoise) & 0x00ffffff) | 0x22000000);
    }

    public void setValues(long[] next) {
        values = next == null ? new long[0] : next.clone();
        invalidate();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (values.length < 2 || getWidth() <= 0 || getHeight() <= 0) return;
        long max = 1;
        for (long value : values) max = Math.max(max, value);
        float step = (float) getWidth() / (values.length - 1);
        float bottom = getHeight() - 2f;
        float usable = Math.max(1f, getHeight() - 4f);
        Path path = new Path();
        for (int i = 0; i < values.length; i++) {
            float x = i * step;
            float y = bottom - usable * values[i] / max;
            if (i == 0) path.moveTo(x, y); else path.lineTo(x, y);
        }
        Path area = new Path(path);
        area.lineTo(getWidth(), bottom);
        area.lineTo(0, bottom);
        area.close();
        canvas.drawPath(area, fill);
        canvas.drawPath(path, line);
    }
}
