# BSD LICENSE
#
# Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import math
import matplotlib as mp
mp.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import itertools

"""
Generate graphs for each test suite

TODO add 3d mesh graph interface
"""
# gap between the first bar graph and the x axis
distanceFromXAxis = 0.2
colors = itertools.cycle([
                         'b',
                         'g',
                         'c',
                         '#008000',
                         '#008FF0', '#0080FF', '#008080', '#808000'])

colors = itertools.cycle([
    '#f70202',
    '#0f0b0b',
    '#123eed',
    '#07601b',
    '#36f760',
    '#87210d',
    '#512f28',
    '#11c6b1',
    '#45f94e',
    '#f94566'
])

barcolors = itertools.cycle([
    '#f70202',
    '#0f0b0b',
    '#123eed',
    '#07601b',
    '#36f760',
    '#87210d',
    '#512f28',
    '#11c6b1',
    '#45f94e',
    '#f94566'
])

expColors = itertools.cycle(['r', 'm', 'y'])
graphNum = 0


class ovGroup:

    def __init__(self):
        self.number = 0
        self.numPipes = 0
        self.tc0inputData = 0
        self.tc3inputData = 0


class graphit2d(object):

    def __init__(self):
        self.graphType = ''
        self.title = ''
        self.xLabel = ''
        self.yLabel = ''
        self.xticks = []
        self.yticks = []

        self.xs = []
        self.ys = []
        self.expectedXs = []
        self.expectedYs = []

        self.barNames = []
        self.barLegends = []
        self.barData = []
        self.barGraphXTitle = ''
        self.barWidth = 0.35
        self.isLineRate = 0


class Plot2DGraph:

    def __init__(self):
        self.numSubPlots = 0
        self.plotName = ''
        self.graphs = []
        self.fig = []
        self.graphType = ''
        self.numPlots = 1
        self.hasLegend = True
        self.legendKeys = []

        self.newXLabel = ''
        self.newXticks = []
        self.newYLabel = ''
        self.newYticks = []
        self.newAxOffset = 60

        self.xticks = []
        self.xticklabels = []
        self.yticks = []
        self.yticklabels = []

        self.alignYmax = False
        self.horizontalLine = False
        self.hLine = 0
        self.hLineBoxX = 3.5
        self.hLineBoxY = 1.021,
        self.hLineName = 'Expected rate'

        self.xLen = 0
        self.yLen = 0
        self.titleFontSize = 0
        self.titleXOffset = 0
        self.titleYOffset = 0

        self.bar_plot_mix = False
        self.lbottomLimit = 1
        self.colorList = []
        self.lineStyleList = []
        self.markerList = []
        self.barDescriptionBoxTxt = []
        self.barTextBoxTxt = []
        self.setBarOverlay = False
        self.child = None
        pass

    def __del__(self):
        if self.child is not None:
            self.child.close(force=True)
            self.child = None


#
# Setup/add data functions
#
    def resetMe(self):
        self.horizontalLine = False
        self.alignYmax = False
        self.bar_plot_mix = False
        self.xLen = 0
        self.yLen = 0
        self.titleFontSize = 0
        self.titleXOffset = 0
        self.titleYOffset = 0
        if self.graphs:
            del self.graphs[:]
        if self.yticks:
            del self.yticks[:]
        if self.yticklabels:
            del self.yticklabels[:]
        if self.xticks:
            del self.xticks[:]
        if self.xticklabels:
            del self.xticklabels[:]
        if self.colorList:
            del self.colorList[:]
        if self.lineStyleList:
            del self.lineStyleList[:]
        if self.markerList:
            del self.markerList[:]
        if self.newXticks:
            del self.newXticks[:]
            self.newXLabel = ''
        if self.newYticks:
            del self.newYticks[:]
            self.newYLabel = ''
        if self.barTextBoxTxt:
            del self.barTextBoxTxt[:]
        if self.barDescriptionBoxTxt:
            del self.barDescriptionBoxTxt[:]

    def setPlotName(self, plotname):
        self.plotName = plotname

    def getPlotName(self):
        return self.plotName

    def setNumSubplots(self, numSubPlots=1):
        """
        Set the number of subplots for a new figure.
        delete previously stored graph data
        """
        self.numSubPlots = numSubPlots

    def setGraphType(self, graphtype='plot'):
        self.graphType = graphtype

    def getGraphType(self):
        return self.graphType

    def getNumSubPlots(self):
        return self.numSubPlots

    def setNumSubPlots(self):
        return self.numSubPlots

    def setNumPlots(self, numPlots=1):
        self.numPlots = numPlots

    def setColors(self, colorlist):
        self.colorList = colorlist

    def setLineStyle(self, lineStylelist):
        self.lineStyleList = lineStylelist

    def setMarkers(self, markerlist):
        self.markerList = markerlist

    def setPutYticksOnFirstAxis(self, yticks, ytickLabels):
        self.yticks = yticks
        self.yticklabels = ytickLabels

    def setPutXticksOnFirstAxis(self, xticks, xtickLabels):
        self.xticks = xticks
        self.xticklabels = xtickLabels

    def setPutXticksOnSecondAxis(self, xticks, xLabel):
        self.newXLabel = xLabel
        self.newXticks = xticks

    def setPutYticksOnSecondAxis(self, yticks, yLabel, axOffset=60):
        self.newYLabel = yLabel
        self.newYticks = yticks
        self.newAxOffset = axOffset

    def addBarDescriptionBoxTxt(self, plotnum, ovGroup=[], position='bottom left'):
        self.barDescriptionBoxTxt.insert(plotnum, ovGroup)

    def setBarTextBoxTxt(self, barText):
        self.barTextBoxTxt = barText

    def setBarWidth(self, plotNum, width):
        self.graphs[plotNum].barWidth = width

    def addBarYlabel(self, plotNum, ylabel):
        self.graphs.insert(plotNum, graphit2d())
        currGraph = self.graphs[plotNum]
        self.graphs[plotNum].yLabel = ylabel

    def setBarLegends(self, plotNum, legends):
        self.graphs[plotNum].barLegends = legends

    def addBarData(self, plotNum, xlabel, dataArray, barGraphXTitle=''):
        self.graphs[plotNum].graphType = 'bar'
        self.graphs[plotNum].barNames.append(xlabel)
        self.graphs[plotNum].barData.append(dataArray)
        self.graphs[plotNum].barGraphXTitle = barGraphXTitle

    def addPlotData(self, plotNum,
                    xlabel, ylabel,
                    xticks, yticks,
                    xData, yData,
                    xExpData, yExpData,
                    graphType='plot',
                    isLineRate=0):
        """
        Add graph object if it doesn't exist
        """
        self.graphs.insert(plotNum, graphit2d())

        currGraph = self.graphs[plotNum]

        currGraph.isLineRate = isLineRate

        if xlabel:
            currGraph.xLabel = xlabel
        if ylabel:
            currGraph.yLabel = ylabel
        if xticks:
            currGraph.xticks = xticks
        if yticks:
            currGraph.yticks = yticks
        if graphType:
            currGraph.graphType = graphType

        if len(xData) != len(yData):
            print 'Error xData = ' + str(len(xData))
            print 'yData = ' + str(len(yData))
            print xData
            print yData
            return

        currGraph.xs = xData
        currGraph.ys = yData

        if xExpData:
            currGraph.expectedXs = xExpData
        if yExpData:
            currGraph.expectedYs = yExpData

    def oneBar(self, ax, graph, key=[]):

        dataSet1 = []
        dataSet2 = []
        width = graph.barWidth

        for data in graph.barData:
            dataSet1.append(data[0])
            dataSet2.append(data[1])

        ind = np.arange(len(dataSet1)) + distanceFromXAxis

        ax.set_xticklabels(graph.barNames)
        rects1 = ax.bar(ind, dataSet1, width, color='#512f28')
        rects2 = ax.bar(ind + width, dataSet2, width, color='#11c6b1')

        if graph.yLabel:
            ax.set_ylabel(graph.yLabel)
        if graph.title:
            ax.set_title(graph.title)

        if graph.barLegends:
            ax.legend((rects1[0], rects2[0]), graph.barLegends)

        ax.set_xticks(ind + width)
        ax.set_xticklabels(graph.barNames)

    def onePlot(self, ax, graph, key=[], lineStyle='-', Marker='x', color=next(colors)):

        if graph.xLabel:
            ax.set_xlabel(graph.xLabel)
        if graph.yLabel:
            ax.set_ylabel(graph.yLabel)

        if graph.xticks:
            ax.set_xticks(range(len(graph.xticks)))
            ax.set_xticklabels(graph.xticks)
        elif self.xticklabels:
            ax.set_xticks(self.xticks)
            ax.set_xticklabels(self.xticklabels)
        if graph.yticks:
            ax.set_yticks(range(len(graph.yticks)))
            ax.set_yticklabels(graph.yticks)
        elif self.yticklabels:
            ax.set_yticks(self.yticks)
            ax.set_yticklabels(self.yticklabels)

        if graph.graphType and graph.graphType == 'bar':

            ind = np.arange(len(graph.xs)) + distanceFromXAxis
            width = graph.barWidth

            if key is not None:
                ax.bar(ind, graph.ys, width=width, color='b', label=key)
            else:
                ax.bar(ind, graph.ys, width=width, color='b')
            ax.set_xticks(ind + width)
            ax.set_xticklabels(graph.xticks)

        else:
            if key is not None:
                ax.plot(graph.xs, graph.ys, color=color,
                        linestyle=lineStyle, marker=Marker, label=key)
            else:
                ax.plot(graph.xs, graph.ys, color=color,
                        linestyle=lineStyle, marker=Marker)

# deprecated
        if graph.expectedXs:
            print 'DEPRECATED'
            return

            if graph.graphType and graph.graphType == 'bar':
                ax.bar(graph.expectedXs,
                       graph.expectedYs,
                       width=1,
                       color=next(expColors),
                       label='Exp' + key)

                plt.xticks(graph.xticks, visible=False)
                plt.yticks(graph.yticks)
            else:
                ax.plot(graph.expectedXs,
                        graph.expectedYs,
                        linestyle='--',
                        color=next(expColors),
                        marker='o', label=key)

    def addnewYaxis(self, fig, oldAx):
        newAx = fig.add_axes(oldAx.get_position())
        newAx.patch.set_visible(False)
        # newAx.yaxis.set_visible(False)
        newAx.spines['left'].set_position(('outward', self.newAxOffset))
        newAx.spines['left'].set_color('r')
        newAx.spines['left'].set_facecolor('r')
        newAx.spines['left'].set_edgecolor('r')

        newAx.set_yticks(range(len(oldAx.get_yticks())))
        newAx.set_yticklabels(self.newYticks[0:len(oldAx.get_yticks())])
        newAx.set_ylabel(self.newYLabel, color='b')
        newAx.yaxis.set_visible(True)
        newAx.xaxis.set_visible(False)

    """
    generate graph(s) function
    """

    def multiBarPlots(self, numPlots, keys=[], Title=[], stack=False):
        fig = plt.figure()
        fig.set_size_inches(15, 10)
        fig.suptitle(Title, fontsize=24, y=0.96)
        self.hasLegend = True
        ax1 = fig.add_axes([0.15, 0.1, 0.72, 0.8])
        rects = []
        lines = []
        lbottoms = [0 for x in range(numPlots)]
        rbottoms = [0 for x in range(numPlots)]
        width = self.graphs[0].barWidth

        for i in range(0, numPlots):
            dataSet = []
            color = color = next(barcolors)
            if self.colorList:
                color = self.colorList[i]
            if (True == stack):
                dataSet = self.graphs[0].barData[i]
                if 1 == len(self.graphs[0].barData[0]):
                    xmin, xmax = plt.xlim()
                    xmax = (width + distanceFromXAxis) * 2
                    plt.xlim(xmin=xmin, xmax=xmax)

                ind = np.arange(len(dataSet)) + distanceFromXAxis
                if self.lbottomLimit > i:
                    del(lbottoms[len(dataSet):])
                    rect = ax1.bar(ind, dataSet, width, color=color,
                                   label=self.graphs[0].barLegends[i],
                                   bottom=lbottoms)
                    j = 0
                    for x in dataSet:
                        lbottoms[j] += x
                        j += 1
                else:
                    del(rbottoms[len(dataSet):])
                    rect = ax1.bar(ind + width, dataSet, width, color=color,
                                   label=self.graphs[0].barLegends[i],
                                   bottom=rbottoms)
                    j = 0
                    for x in dataSet:
                        rbottoms[j] += x
                        j += 1
            else:
                for data in self.graphs[0].barData:
                    dataSet.append(data[i])
                ind = np.arange(len(dataSet)) + distanceFromXAxis
                rect = ax1.bar(ind + (width * i), dataSet, width,
                               label=self.graphs[0].barLegends[i],
                               color=color)

            rects.append(rect)

            del dataSet[:]

        if (True == stack):
            ymin, ymax = plt.ylim()
            if ymax > (math.ceil(ymax) - 0.5):
                ymax = math.ceil(ymax) + 1
            else:
                ymax = math.ceil(ymax)
            plt.ylim(ymin=ymin, ymax=ymax)

        if self.newYticks:
            self.addnewYaxis(fig, ax1)

        # Draw a horizontal red line like a champion
        if True == self.horizontalLine:
            plt.axhline(y=self.hLine, color='r')
            ax1.text(self.hLineBoxX, self.hLineBoxY, self.hLineName, bbox=dict(facecolor='red', alpha=0.5))

# TODO merge this into a single loop for plots and bar graphs
        if True == self.bar_plot_mix:
            color = color = next(barcolors)
            for graph in self.graphs:
                if graph.graphType == 'bar':
                    continue
                colorOffset = numPlots
                if self.colorList:
                    color = self.colorList[colorOffset]
                    colorOffset += 1

                line = ax1.plot(graph.xs,
                                graph.ys,
                                marker='x',
                                color=color, label=graph.xLabel)

        if self.graphs[0].yLabel:
            ax1.set_ylabel(self.graphs[0].yLabel, fontsize=18)
        if self.graphs[0].title:
            ax1.set_title(self.graphs[0].title)

        if True == stack:
            # ax1.set_xticks(ind + (width * 1.5))
            # ax1.set_xticks(ind + width)
            ax1.set_xticks(ind + width * .5)
            # ax1.set_xticklabels(self.graphs[0].barNames[2:6])
            # ax1.set_xticklabels(self.graphs[0].barNames[1:5])
            ax1.set_xticklabels(self.graphs[0].barNames[0:4])
            # ax1.legend(rects[:], self.graphs[0].barLegends, fontsize=12, loc='upper right')
            ax1.legend()
            if self.barTextBoxTxt:
                text = ''
                # fp = dict(size=10)
                x0 = 0.03
                y0 = 1.2
                for text in self.barTextBoxTxt:
                    at = ax1.annotate(text, xy=(x0, y0),
                                      bbox=dict(boxstyle="round", fc="w"))
                    ax1.add_artist(at)
                    x0 += 1

#                _at = AnchoredText(text, loc=2, prop=fp)

        else:
            ax1.set_xticks(ind + (width * (numPlots / 2)))
            ax1.set_xticklabels(self.graphs[0].barNames)
            # ax1.legend(rects[:], self.graphs[0].barLegends)
            ax1.legend()
            # plt.legend(bbox_to_anchor=(0.9, 0.9, 0.1, 0.1),
            #           bbox_transform=plt.gcf().transFigure,
            #           fontsize=12)

# TODO complete this function
    def addDescBoxTxt(self, ax, ovDescs):
        #        plt.setp(ax.get_xticklabels, visible=False)
        #        plt.setp(ax.get_yticklabels, visible=False)
        # x_axis = ax.get_xaxis()
        # y_axis = ax.get_yaxis()

        # x_axis.set_visible(False)
        # y_axis.set_visible(False)

        ax.set_visible(False)

        # at = ax1.annotate(text, xy=(x0, y0),
        #                  bbox=dict(boxstyle="round", fc="w"))
        # ax1.add_artist(at)
        # x0 += 1

    def fourBarGraphs(self, numGraphs, keys=[], Title=[]):
        # get max value to be displayed
        if True == self.alignYmax:
            maxval = 0.3
            for graph in self.graphs:
                for x in graph.barData:
                    for y in x:
                        if y > maxval:
                            maxval = y + 0.1

        fig, aXarr = plt.subplots(2, 2)
        # fig.suptitle(Title, fontsize=24, y=0.96)
        fig.suptitle(Title, fontsize=24)
        fig.set_size_inches(15, 10)

        x_range = [0, 1]
        y_range = [0, 1]
        k = 0

        numSubPlotDisplay = self.numSubPlots + 1

        for i in x_range:
            for j in y_range:
                numSubPlotDisplay -= 1
                if 0 >= numSubPlotDisplay:
                    if self.barDescriptionBoxTxt:
                        # addDescBoxTxt(aXarr[i][j], self.barDescriptionBoxTxt)
                        aXarr[i][j].set_visible(False)
                    else:
                        aXarr[i][j].set_visible(False)
                    continue
                if True == self.alignYmax:
                    aXarr[i][j].set_ylim(ymax=maxval, ymin=0)

                if keys:
                    self.oneBar(aXarr[i][j], self.graphs[k], keys[k])
                else:
                    self.oneBar(aXarr[i][j], self.graphs[k])
                if '' != self.graphs[k].barGraphXTitle:
                    aXarr[i][j].set_xlabel(self.graphs[k].barGraphXTitle)

                if self.newYticks and (0 == j):
                    self.addnewYaxis(fig, aXarr[i][0])
                # graph reference
                k += 1

        plt.legend(bbox_to_anchor=(0.9, 1.1), loc = 'upper center')
#        plt.setp([a.get_xticklabels() for a in aXarr[0, :]], visible=False)
#        plt.setp([a.get_yticklabels() for a in aXarr[:, 1]], visible=False)

    def multiGraph(self, numGraphs, keys=[]):
        self.fig = plt.figure()
        self.hasLegend = True
        graphNum = 0
        color = next(colors)
        for i in range(0, numGraphs):
            marker = 'x'
            lineStyle = '-'
            if self.lineStyleList:
                lineStyle = self.lineStyleList[i]
            if self.markerList:
                marker = self.markerList[i]
            if self.colorList:
                color = self.colorList[i]

            graphNum += 1
            key = []
            if keys is not None:
                key = keys[i]
            subplotnum = int(str(numGraphs) + str(1) + str(i))
            self.onePlot(self.fig.add_subplot(subplotnum),
                         self.graphs[i],
                         key,
                         color=color,
                         lineStyle=lineStyle,
                         Marker=marker)

        if self.newXticks:
            # TODO - this is broken, needs to be moved into the above loop maybe..
            newAx = self.fig.add_axes(ax.get_position())
            newAx.patch.set_visible(False)
            newAx.yaxis.set_visible(False)

            newAx.spines['bottom'].set_position(('outward', 50))
            # newAx.spines['bottom'].set_color('red')
            # newAx.spines['bottom'].set_facecolor('red')
            # newAx.spines['bottom'].set_edgecolor('red')

            newAx.set_xticks(range(len(self.newXticks)))
            newAx.set_xticklabels(self.newXticks)
            newAx.set_xlabel(self.newXLabel, color='b')
            newAx.xaxis.set_visible(True)

        if keys is not None:
            plt.legend(bbox_to_anchor=(0.9, 1.1), loc = 'upper center')

    def multiPlots(self, numPlots, keys=[], Title=[]):
        self.fig = plt.figure()
        self.fig.set_size_inches(15, 10)
        newAx = []

        titleFontSize = self.titleFontSize
        titleYOffset = self.titleYOffset
        titleXOffset = self.titleXOffset
        if 0 == self.titleFontSize:
            titleFontSize = 24
        if 0 == self.titleYOffset:
            titleYOffset = 0.96
        if 0 == self.titleXOffset:
            self.fig.suptitle(Title, fontsize=titleFontSize, y=titleYOffset)
        else:
            self.fig.suptitle(Title, fontsize=titleFontSize, y=titleYOffset, x=titleXOffset)

        self.hasLegend = True
        graphNum = 0
        if self.newXticks:
            newAx = self.fig.add_axes([0.05, 0.1, 0.72, 0.8])
            newAx.patch.set_visible(False)
            newAx.yaxis.set_visible(False)

            newAx.spines['bottom'].set_position(('outward', 35))
            newAx.spines['bottom'].set_color('r')
            newAx.spines['bottom'].set_facecolor('r')
            newAx.spines['bottom'].set_edgecolor('r')

            newAx.set_xticks(range(len(self.newXticks)))
            newAx.set_xticklabels(self.newXticks)
            newAx.set_xlabel(self.newXLabel, color='b')
            newAx.xaxis.set_visible(True)

        if newAx:
            ax = self.fig.add_axes(newAx.get_position())
        else:
            xLen = self.xLen
            yLen = self.yLen
            if 0 == self.xLen:
                xLen = 0.72
            if 0 == self.yLen:
                yLen = 0.8

            ax = self.fig.add_axes([0.05, 0.1, xLen, yLen])

        for i in range(0, numPlots):
            marker = 'x'
            lineStyle = '-'
            color = next(colors)
            if self.lineStyleList:
                lineStyle = self.lineStyleList[i]
            if self.markerList:
                marker = self.markerList[i]
            if self.colorList:
                color = self.colorList[i]

            graphNum += 1
            if keys is not None:
                self.onePlot(ax,
                             self.graphs[i],
                             keys[i],
                             color=color,
                             lineStyle=lineStyle,
                             Marker=marker)
            else:
                self.onePlot(ax,
                             self.graphs[i],
                             color=color,
                             lineStyle=lineStyle,
                             Marker=marker)

        if True == self.horizontalLine:
            plt.axhline(y=self.hLine, color='r')
            ax.text(self.hLineBoxX, self.hLineBoxY, self.hLineName, bbox=dict(facecolor='red', alpha=0.5))

        # plt.legend(bbox_to_anchor=(0.9, 1.1), loc = 'upper center')
        if keys is not None:
            plt.legend(bbox_to_anchor=(0.9, 0.9, 0.1, 0.1),
                       bbox_transform=plt.gcf().transFigure,
                       fontsize=12)

    def generatePlot(self, plotName='output.jpg',
                     keys=None, title=[],
                     firstYvalue=0, firstXvalue=0):
        """check num subplots is not too much"""

        if(self.numSubPlots > 4):
            print "Max subplots exceeded: " + str(self.numSubPlots)
            return

        # generate graphs, write to file
        if(self.numPlots > 1):
            self.multiPlots(self.numPlots, keys, title)
        else:
            self.multiGraph(self.numSubPlots, keys)

        # write to file
        if 0 < firstYvalue:
            ymin, ymax = plt.ylim()
            if ymax == math.ceil(ymax):
                ymax += 2
            else:
                ymax = math.ceil(ymax) + 2
            # ymin = ymax - 2
            ymin = 0
            plt.ylim(ymin=ymin, ymax=ymax)

        xmin, xmax = plt.xlim()
        xmin = 0
        plt.xlim(xmin=xmin, xmax=xmax)
        plt.savefig(plotName)

    def generateBar(self, plotName='output.jpg', keys=[], title=[]):

        if True == self.setBarOverlay:
            self.multiBarPlots(self.numPlots, keys, title, stack=True)
        else:
            if self.numSubPlots > 1:
                self.fourBarGraphs(self.numSubPlots, keys, title)
            else:
                self.multiBarPlots(self.numPlots, keys, title)

        plt.savefig(plotName)
