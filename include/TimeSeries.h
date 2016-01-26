/*
 *
 * (C) 2013-16 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifndef _TIMESERIES_H_
#define _TIMESERIES_H_

typedef struct datapoint{
    float x;
    float y;
} datapoint;

class TimeSeries {
private:
    u_int32_t num_datapoints, next_datapoint_index;
    float ewma_aplha;
    float latest_derivative, latest_derivatives_ewma;
    float derivatives_sum;
    datapoint datapoints[2];

    void deriveLastDatapoints();
    inline float radiants2degrees(float radiants){return radiants * (180. / 3.141592);};
    inline void updateDerivativesSum(){derivatives_sum += latest_derivative;};
    // the Exponential Weighted Moving Average for Derivatives
    inline void updateDerivativesEWMA(){
        latest_derivatives_ewma =
                (1 - ewma_aplha) * latest_derivatives_ewma 
                + ewma_aplha * latest_derivative;};

public:
    TimeSeries(double _ewma_alpha = .5);
    u_int8_t addDataPoint(float x, float y);
    float getAvgDerivative(bool normalized);
    float getDerivativeEWMA(bool normalized);
};


#endif /* _TIMESERIES_H_ */

