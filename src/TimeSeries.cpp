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

#include "ntop_includes.h"

TimeSeries::TimeSeries(double _ewma_alpha){
    if (_ewma_alpha > 1) _ewma_alpha = 1;
    if (_ewma_alpha < 0) _ewma_alpha = 0;
    ewma_aplha = _ewma_alpha;
    num_datapoints = next_datapoint_index = 0;
    latest_derivative = latest_derivatives_ewma = 0;
    memset(&datapoints, 0, sizeof(datapoints));
}


u_int8_t TimeSeries::addDataPoint(float x, float y){
    if(x != 0 and y != 0)
        ntop->getTrace()->traceEvent(TRACE_DEBUG,
                "Adding datapoint: x=%.2f y=%.2f", x, y);
    // before overwriting the older datapoint, we need to make
    // sure statistics are updated.
    deriveLastDatapoints();
    updateDerivativesSum();
    updateDerivativesEWMA();
    // now we can overwrite
    datapoints[next_datapoint_index].x = x;
    datapoints[next_datapoint_index].y = y;
    next_datapoint_index = (next_datapoint_index + 1) % 2;
    num_datapoints++;
    return 0;
}

void TimeSeries::deriveLastDatapoints() {
    if (num_datapoints <= 1) return; // we need at least two points
    u_int8_t newer = next_datapoint_index == 1 ? 0 : 1;
    u_int8_t older = next_datapoint_index == 0 ? 0 : 1;
    if(datapoints[newer].x == datapoints[older].x) return; // prevent zero-division errors
    latest_derivative = (datapoints[newer].y - datapoints[older].y) / (datapoints[newer].x - datapoints[older].x);
}

float TimeSeries::getAvgDerivative(bool normalized){
    // average the derivative
    float d_sum = derivatives_sum / (float)num_datapoints;
    if (!normalized)
        return d_sum;
    else{
        // obtain the angle theta that the average slopes have with the x-axis
        return radiants2degrees(atan(d_sum));
    }
}

float TimeSeries::getDerivativeEWMA(bool normalized){
    return normalized ? radiants2degrees(atan(latest_derivatives_ewma)) : latest_derivatives_ewma;
}