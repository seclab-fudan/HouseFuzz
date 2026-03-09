# HouseFuzz

HouseFuzz: Service-Aware Grey-Box Fuzzing for Vulnerability Detection in Linux-Based Firmware.

## Overview

![overview](https://github.com/user-attachments/assets/4df1f721-47a8-4b4b-b5a6-32400047ac42)

## Open-source Status

To facilitate the replication of the paper experiments, we've built and uploaded HouseFuzz's docker image at [DockerHub](https://hub.docker.com/r/kenshin123/housefuzz)

## step0: files prepare
The images mentioned in the paper can be found at /Housefuzz/all_images.  

You can choose the images you want to analyze and copy them to [path_to_corpus]/images.  

For new images you want to analyze, you can copy it to [path_to_corpus]/images and copy the corresponding output of grennhouse to the results directory [path_to_corpus]/results.

The source script to generate the dictionary can be found at /Housefuzz/dict_gen.  

You need to copy the sorce folder to your ida workplace and edit IDA_PATH at line 5 in main.py to specify the ida you want to use.  
```
python src/main.py -i [path to binary] -d [path to log] -f [output file name] -c 1 -o [path to output folder]
```
You can generate the dictionary for fuzzing using this command.  

The dictionary should be copied to [path_to_corpus]/[static_result]/[barnd]/[name_of_image]/ in the container.  

We test it on windows11 with ida7.7.  

You also need to copy the output file of SaTC, api.dict, to the same path, [path_to_corpus]/[static_result]/[barnd]/[name_of_image]/ in the container.  

## step1: initial analysis
```
tools/service_analysis.sh hf_gen [path_to_corpus]
```
This command will generate file command.sh at [path_to_corpus]/initial_analysis/.

```
tools/service_analysis.sh hf_run [path_to_corpus]
```
This command will run command.sh to analyse the service binaries.

```
tools/service_analysis.sh hf_collect [path_to_corpus]
```
The command will print the result of initial analysis.

## step2: build fuzzing images

```
python3 tools/gen_hf_image_cmds.py [path_to_corpus]
```
This command will generate file command.sh at [path_to_corpus]/fuzzing/.

```
sh [path_to_corpus]/fuzzing/commands.sh
```
This command will automatically build all the fuzzing images.

## step2: run the fuzzing image

Environment variables below are supported.

| Var               | Description                                         |
|-------------------|-----------------------------------------------------|
| ROUND             | fuzzing output will be found at `"scratch_${ROUND}"`|
| GH_YES            | GREENHOUSE                                          |
| HF_NO_CFG         | HouseMP                                             |
| HF_NO_TDG_ONLINE  | HOUSECFG                                            |
| HF_NO_TDG_OFFLINE | HOUSETDGOL                                          |

Detailed descriptions of the environment variables can be found in the paper.  

The fuzzing images will run as Housefuzz if no environment variables are set.  

```
python3 tools/hf_fuzz.py [path_to_corpus]
```
You can run images in batches using this command.

```
cd [path_to_corpus]/fuzzing/hf/[brand]/[name of image]/p80
./run.sh
```
You can run images manually using this command.


