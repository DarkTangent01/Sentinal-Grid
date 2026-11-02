// Tree-shaken ECharts: only the series and components this app renders are bundled (the full "echarts" entry
// pulls every chart type). Add the matching chart/component here before using a new series type or option key:
// a missing one fails silently (the option is ignored).
import * as echarts from "echarts/core";
import { BarChart, CustomChart, GaugeChart, GraphChart, HeatmapChart, LineChart, MapChart, PieChart, RadarChart } from "echarts/charts";
import {
  AriaComponent, CalendarComponent, DatasetComponent, GraphicComponent, GridComponent, LegendComponent, MarkAreaComponent,
  MarkLineComponent, TitleComponent, TooltipComponent, VisualMapComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";

echarts.use([
  BarChart, CustomChart, GaugeChart, GraphChart, HeatmapChart, LineChart, MapChart, PieChart, RadarChart,
  AriaComponent, CalendarComponent, DatasetComponent, GraphicComponent, GridComponent, LegendComponent, MarkAreaComponent,
  MarkLineComponent, TitleComponent, TooltipComponent, VisualMapComponent, CanvasRenderer,
]);

export { echarts };
