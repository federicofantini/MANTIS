# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 Federico Fantini


# [EXPLAINATION]:   https://sagi-z.github.io/BackgroundSubtractorCNT/doxygen/html/index.html
# [SOURCE CODE]:    https://github.com/sagi-z/BackgroundSubtractorCNT
# [DEMO]:           https://sagi-z.github.io/BackgroundSubtractorCNT/doxygen/html/python_2demo_8py-example.html

from .log import logger

import av
import cv2
import time
import numpy as np
import cv2.bgsegm
import threading
from io import BytesIO
from typing import Callable


class Task:
    def __init__(self, name, value=None):
        self.name = name
        self.value = value

# Running in a dedicated thread
class AlarmSystem(threading.Thread):
    def __init__(self, mantis, alarm_capture_seconds=20, background_ratio=0.90):
        super().__init__(name="AlarmSystemThread")

        self.mantis = mantis
        self.alarm_capture_seconds = alarm_capture_seconds
        self.background_ratio = background_ratio

        self.tasks = []
        self.force_exit = False
        self.condition_lock = threading.Condition()
        self.record_video = -1
        self.take_picture = False
        self.enable_alarm_system = False
        self.alarm_count = 0
        self.capture = False
        self.stabilized = False
        self.init_camera = False
    
    # Setup camera, measure real FPS, configure background subtraction
    def _init_camera(self):
        if not hasattr(self, "cap") or hasattr(self, "cap") and not self.cap.isOpened():
            self.cap = cv2.VideoCapture(0)
        
        if not self.cap.isOpened():
            logger.error("Cannot open camera")

        # Dynamic fps measure instead of int(self.cap.get(cv2.CAP_PROP_FPS))
        if not hasattr(self, "fps"):
            frame_counter = 0
            measure_frames = 200
            start_time = time.perf_counter()
            while frame_counter < measure_frames:
                ret, frame = self.cap.read()
                if not ret:
                    break
                frame_counter += 1

                # Simulate the workload
                cv2.GaussianBlur(frame, (5, 5), 0)  # pre-processing
                foreground_mask = cv2.medianBlur(frame, 5) # foreground mask
                foreground_mask = cv2.erode(foreground_mask, np.ones((5, 5), np.uint8), iterations=2) # foreground mask
                _, compressed = cv2.imencode('.jpg', frame) # compression?

            end_time = time.perf_counter()

            # Real fps
            elapsed = end_time - start_time
            fps_reale = frame_counter / elapsed
            print(f"Measured real FPS: {fps_reale:.2f}")
            self.fps = int(fps_reale)
        
        self.width = int(self.cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        self.height = int(self.cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        self.threshold = self.fps * 1.5 # We want an alarm if there has been a movement of at least 1.5s
        # Detect motion via BackgroundSubtractorCNT
        self.backgroundDetector = cv2.bgsegm.createBackgroundSubtractorCNT(
            minPixelStability=self.fps,
            useHistory=True,
            maxPixelStability=30*self.fps,
            isParallel=True,
        )

    # exit the thread loop
    def exit(self):
        logger.info("force exit the thread!")
        self.force_exit = True
        with self.condition_lock:
            self.condition_lock.notify()

    # Queue a task: enable alarm / take picture / record video
    def add_task(self, task: str = "alarm_system", enable_alarm_system: bool = True, record_video_duration: int = 10) -> None:
        logger.info(f"add_task task={task} enable_alarm_system={enable_alarm_system} record_video_duration={record_video_duration}")

        match task:
            case "alarm_system":
                self.enable_alarm_system = enable_alarm_system
                # if we are activating the camera after a while we have to redo the stabilization
                if not self.enable_alarm_system and enable_alarm_system:
                    self.stabilized = False
                    self.init_camera = False
                    if hasattr(self, "cap"):
                        self.cap.release()
            case "take_picture":
                self.tasks.append(Task("take_picture", True))
            case "record_video":
                self.tasks.append(Task("record_video", record_video_duration))
            case _:
                pass

        if self.tasks or self.enable_alarm_system or self.record_video > 0 or self.take_picture:
            logger.info("add_task: notify")
            with self.condition_lock:
                self.condition_lock.notify()

    # NOTE: The architecture now uses threading.Condition for efficient synchronization.
    #       The AlarmSystem runs on a dedicated thread separate from Python's main thread.
    #       Synchronization between threads is managed via a shared Condition object, which
    #       allows the AlarmSystem to wait without consuming CPU when idle, and to be
    #       promptly notified when new tasks are added. This avoids busy-waiting loops and
    #       ensures efficient, thread-safe task injection from the main thread.
    def run(self) -> None:
        # an initialization placeholder for the save_video_and_send closure
        def save_video_and_send(*args, **kwargs) -> None:
            pass

        c = 0
        next_frame_time = time.perf_counter()

        while True:

            # nothing to do -> sleeping!
            while not (self.force_exit or self.tasks or self.enable_alarm_system or self.record_video > 0 or self.take_picture):
                logger.info("Waiting for tasks...")
                with self.condition_lock:
                    self.condition_lock.wait()

            # exit?
            if self.force_exit:
                break

            # check if we have to record something -> one at a time
            if not self.record_video > 0 and not self.take_picture:
                if self.tasks:
                    task = self.tasks.pop(0)
                    match task.name:
                        case "take_picture":
                            logger.info("Added take_picture task.")
                            self.take_picture = task.value
                        case "record_video":
                            logger.info(f"Added record_video of {task.value}s task.")
                            self.record_video = task.value

            if not self.init_camera:
                self._init_camera()
                self.init_camera = True
            
            # capture frame-by-frame
            ret, frame = self.cap.read()

            # if frame is read correctly ret is True
            if not ret or frame is None:
                logger.error("Can't receive frame (stream end?). Exiting ...")
                break
            
            if not self.stabilized and not self.take_picture and not self.record_video > 0:
                c += 1
                if c < self.backgroundDetector.getMaxPixelStability():  # wait background stability
                    continue
                else:
                    self.stabilized = True
                    logger.info("Background stabilized!")

            # If motion or manual recording triggered → save the video
            if self.capture:
                save_video_and_send(frame)
            
            # If task is take_picture → just send the picture
            if self.take_picture:
                self.take_picture = False
                self.send_picture(frame)

            # [PRE-PROCESSING CURRENT FRAME]
            frame = cv2.GaussianBlur(src=frame, ksize=(3, 3), sigmaX=0)

            # [MODEL UPDATE and FOREGROUND MASK]
            foreground_mask = self.backgroundDetector.apply(frame)
            foreground_mask = cv2.medianBlur(foreground_mask, 5)
            foreground_mask = cv2.erode(foreground_mask, np.ones((5, 5), np.uint8), iterations=2)
            
            # [AREA BASED DETECTION] + MANUALLY [RECORD VIDEO / TAKE PICTURE] 
            if ((not self.capture) and
                (
                    # AREA BASED DETECTION
                    (self.enable_alarm_system and (np.sum(foreground_mask) > (1-self.background_ratio)*self.width*self.height)) or
                    # RECORD VIDEO
                    self.record_video > 0
                )
            ):
                # threshold
                if self.enable_alarm_system:
                    self.alarm_count += 1
                    if self.alarm_count < self.threshold:
                        continue
                
                self.capture = True  # capturing is in OR between manual and alarm method
                
                # NOTE: The returned closure must be called sequentially with new frames
                #       during the video capture process. The closure maintains its own internal state.
                if self.record_video > 0:
                    save_video_and_send = self.save_video(frame, self.record_video)
                elif self.enable_alarm_system:
                    save_video_and_send = self.save_video(frame, self.alarm_capture_seconds, is_alarm=True)
                    logger.info("ALARM: something is moving!!!")

            # Sleep until the scheduled frame time + update time to maintain sync
            time.sleep(max(0, next_frame_time - time.perf_counter()))
            next_frame_time += 1 / self.fps

        if hasattr(self, "cap"):
            self.cap.release()
    
    # Capture a single frame and upload using Mantis.upload_image()
    def send_picture(self, frame: np.ndarray) -> None:
        self.mantis.upload_image(
            image_data=cv2.imencode('.png', frame)[1].tobytes(),
            height=self.height,
            width=self.width,
        )

    # Record video frames and upload using Mantis.upload_video()
    # NOTE: generates a closure that incrementally records video frames.
    def save_video(self, frame: np.ndarray, capture_seconds: int, is_alarm: bool = False) -> Callable:
        current_frame = 0
        thumbnail_frame = None
        in_mem_file = BytesIO()
        output = av.open(in_mem_file, 'w', format="mp4")
        stream = output.add_stream('h264', rate=self.fps)
        stream.width = self.width
        stream.height = self.height
        stream.pix_fmt = 'yuv420p'

        # NOTE: This design avoids using global state by returning an internal function (store_frame),
        #       which captures the necessary variables (e.g., capture_seconds, is_alarm, current_frame, 
        #       thumbnail_frame) through lexical scoping.
        #       Each call to the returned closure appends a frame to the video stream until the specified 
        #       capture duration is reached, at which point the video is finalized and uploaded asynchronously.
        def store_frame(frame: np.ndarray) -> None:
            nonlocal capture_seconds
            nonlocal is_alarm
            nonlocal current_frame
            nonlocal thumbnail_frame
            
            if current_frame > capture_seconds * self.fps:
                output.mux(stream.encode(None)) # flush
                output.close()

                self.mantis.upload_video(
                    video_data=in_mem_file.getvalue(),
                    thumbnail_data=thumbnail_frame,
                    duration=capture_seconds*1000, # milliseconds to seconds
                    height=self.height,
                    width=self.width,
                    is_alarm=is_alarm,
                )

                self.capture = False
                if self.record_video > 0:
                    self.record_video = -1
                self.alarm_count = 0
            else:
                if current_frame == 0:
                    thumbnail_frame = cv2.imencode('.png', frame)[1].tobytes()
                video_frame = av.VideoFrame.from_ndarray(frame, format='bgr24')
                output.mux(stream.encode(video_frame))
                current_frame += 1
        
        return store_frame
