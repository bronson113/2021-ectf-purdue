# 2021 Collegiate eCTF
# Remove SED Dockerfile
# Ben Janis
#
# (c) 2021 The MITRE Corporation

# 2021 Purdue Team note:
# Bronson Yen
#
# run remove_secrets.py to update the registration number list
#

# load current SSS container to modify
# NOTE: only sss/ and its subdirectories in the repo are accessible to this Dockerfile as .
ARG DEPLOYMENT
FROM ${DEPLOYMENT}/sss

ARG SCEWL_ID

# do whatever you need to remove the SED from the deployment
RUN python3 /secrets/remove_secrets.py ${SCEWL_ID}
