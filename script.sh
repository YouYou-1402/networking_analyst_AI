#!/bin/bash

# Base directory
BASE="interfaces/gui"

# Create directories
mkdir -p $BASE/widgets
mkdir -p $BASE/dialogs
mkdir -p $BASE/models
mkdir -p $BASE/utils
mkdir -p $BASE/resources/icons
mkdir -p $BASE/resources/styles

# Create files
touch $BASE/main.cpp
touch $BASE/main_window.hpp
touch $BASE/main_window.cpp

# Widgets
for f in \
    packet_list_widget \
    packet_detail_widget \
    packet_hex_widget \
    filter_bar_widget \
    status_bar_widget \
    statistics_widget
do
    touch $BASE/widgets/${f}.hpp
    touch $BASE/widgets/${f}.cpp
done

# Dialogs
for f in \
    capture_dialog \
    preferences_dialog \
    about_dialog \
    export_dialog \
    find_packet_dialog
do
    touch $BASE/dialogs/${f}.hpp
    touch $BASE/dialogs/${f}.cpp
done

# Models
for f in \
    packet_table_model \
    packet_tree_model
do
    touch $BASE/models/${f}.hpp
    touch $BASE/models/${f}.cpp
done

# Utils
for f in \
    color_rules \
    column_config \
    gui_utils
do
    touch $BASE/utils/${f}.hpp
    touch $BASE/utils/${f}.cpp
done

# Resource file
touch $BASE/resources/resources.qrc

echo "Project structure created successfully!"
