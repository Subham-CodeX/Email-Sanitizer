import axios from "axios";

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1",
  timeout: 30000,
});

export type Address={display_name?:string|null;address?:string|null};
export type Attachment={filename:string;content_type?:string|null;content_disposition?:string|null;size_bytes:number;sha256:string};
export type Url={url:string;scheme?:string|null;hostname?:string|null;domain?:string|null;path?:string|null};
export type Metadata={
  subject?:string|null;date?:string|null;message_id?:string|null;
  from:Address[];to:Address[];cc:Address[];bcc:Address[];replyTo:Address[];
  returnPath?:string|null;mime_type?:string|null;content_type?:string|null;
  size_bytes:number;has_plain_text:boolean;has_html:boolean;
  attachment_count:number;url_count:number;
};
export type Result={
  evidence_id:string;input_type:"eml"|"raw_email";filename?:string|null;
  received_at:string;evidence_sha256:string;metadata:Metadata;
  attachments:Attachment[];urls:Url[];body_preview?:string|null;status:string;
};
export async function getHealth(){return (await api.get("/health")).data;}
export async function ingestEml(file:File){
  const fd=new FormData(); fd.append("file",file);
  return (await api.post<Result>("/emails/ingest/eml",fd)).data;
}
export async function ingestRaw(raw_email:string){
  return (await api.post<Result>("/emails/ingest/raw",{raw_email})).data;
}
