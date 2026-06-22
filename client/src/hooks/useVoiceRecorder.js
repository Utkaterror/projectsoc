import { useRef, useState } from "react";

// Определяем поддерживаемый формат один раз при загрузке модуля
function getSupportedMimeType() {
  const types = [
    "audio/webm;codecs=opus",
    "audio/webm",
    "audio/mp4",
    "audio/aac",
    "audio/ogg;codecs=opus",
  ];
  for (const type of types) {
    if (MediaRecorder.isTypeSupported(type)) return type;
  }
  return ""; // браузер выберет сам
}

const MIME_TYPE = getSupportedMimeType();

// Расширение файла по mime-типу
function getExtension(mimeType) {
  if (mimeType.includes("mp4") || mimeType.includes("aac")) return "mp4";
  if (mimeType.includes("ogg")) return "ogg";
  return "webm";
}

export function useVoiceRecorder() {
  const mediaRecorderRef = useRef(null);
  const chunksRef = useRef([]);
  const streamRef = useRef(null);

  const [isRecording, setIsRecording] = useState(false);

  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      streamRef.current = stream;

      const options = MIME_TYPE ? { mimeType: MIME_TYPE } : {};
      const mediaRecorder = new MediaRecorder(stream, options);

      chunksRef.current = [];

      mediaRecorder.ondataavailable = (event) => {
        if (event.data && event.data.size > 0) {
          chunksRef.current.push(event.data);
        }
      };

      mediaRecorderRef.current = mediaRecorder;
      mediaRecorder.start();
      setIsRecording(true);
    } catch (error) {
      console.error("Recording error:", error);
    }
  };

  const stopRecording = () =>
    new Promise((resolve) => {
      const recorder = mediaRecorderRef.current;

      if (!recorder) {
        resolve(null);
        return;
      }

      recorder.onstop = () => {
        const mimeType = recorder.mimeType || MIME_TYPE || "audio/webm";
        const ext = getExtension(mimeType);

        const blob = new Blob(chunksRef.current, { type: mimeType });

        streamRef.current?.getTracks().forEach((track) => track.stop());
        streamRef.current = null;
        setIsRecording(false);

        // Возвращаем blob и расширение — клиент использует правильное имя файла
        resolve({ blob, ext });
      };

      recorder.stop();
    });

  return {
    isRecording,
    startRecording,
    stopRecording,
  };
}