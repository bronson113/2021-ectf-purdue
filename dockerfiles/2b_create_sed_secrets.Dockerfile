# 2021 Collegiate eCTF
# Generate SED secrets Dockerfile
# Ben Janis
#
# (c) 2021 The MITRE Corporation

# 2021 Purdue Team note:
# Bronson Yen
#
# this file calls the create_secrets.py which creates the $(scewl_id).secret file for each sed added
#

# load current SSS container to modify
ARG DEPLOYMENT
FROM ${DEPLOYMENT}/sss

ARG SCEWL_ID

# NOTE: only sss/ and its subdirectories in the repo are accessible to this Dockerfile as .
# NOTE: to maximize the useage of container cache, use ADD to map in only the files/directories you need
#       (e.g. only mapping in the SED directory rather than the entire repo)

# do here whatever you need here to create secrets for the new SED that the SSS needs access to

RUN touch /secrets/${SCEWL_ID}.secret  
RUN python3 /secrets/create_secrets.py ${SCEWL_ID}
